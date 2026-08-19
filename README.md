# Integrating an Application with the ID Card via NFC

- [Using the Library in the Sample Application](#using-the-library-in-the-sample-application) 
  - [Define the Android SDK Location](#define-the-android-sdk-location)   
  - [Installing the Sample Application on a Device or Emulator](#installing-the-sample-application-on-a-device-or-emulator)  
  - [Building only the Sample App APK](#building-only-the-sample-app-apk) 
  - [Testing with the Demo App](#testing-with-the-demo-app)  
  - [Using the Libraries in Other Applications](#using-the-libraries-in-other-applications) 
    - [Building the AAR](#building-the-aar) 
    - [Versioning the AAR](#versioning-the-aar) 
    - [Reporting the Library Version](#reporting-the-library-version) 
    - [Integrator Dependencies](#integrator-dependencies) 
    - [Minimum SDK and Core Library Desugaring](#minimum-sdk-and-core-library-desugaring) 
- [Overview](#overview) 
- [NFC Interface](#nfc-interface) 
  - [General Communication Scheme](#general-communication-scheme) 
  - [NFC Interface Status](#nfc-interface-status) 
  - [Exception Handling](#exception-handling) 
  - [Specifics of the NFC Interface](#specifics-of-the-nfc-interface) 

## Using the Library in the Sample Application

### Define the Android SDK Location

```shell
echo "sdk.dir=/path/to/android-sdk" > local.properties
```

### Installing the Sample Application on a Device or Emulator

To install on a physical device, ensure the device is connected to your computer via a USB cable.

```shell
./gradlew installDebug
```

> [!TIP]
> See also the official Android documentation for
> [installing an app on a physical device](https://developer.android.com/studio/run/device)
> or [in an emulator](https://developer.android.com/studio/run/emulator).

### Building only the Sample App APK

```shell
./gradlew assembleDebug
```

The generated APK file is located at `/demoapp/app/build/outputs/apk/debug`.

### Testing with the Demo App
The demo application (`demoapp/app`) provides a complete reference implementation for NFC ID card integration. It demonstrates:
* **Reading personal data** from the ID card
* **Digital signing** with PIN2 (creates ASiC-E containers using [libdigidocpp](https://github.com/open-eid/libdigidocpp))
* **Authentication** with PIN1 (mock Web-eID implementation)
* **Exception handling** for various error scenarios
**Prerequisites for testing:**
* An Android device with NFC capability (NFC-enabled emulators do not support physical NFC cards)
* A supported NFC-enabled ID card — Estonian (IDEMIA or Thales) or Latvian (IDEMIA)
* The card's CAN code (6-digit number printed on the card)
* PIN1 and/or PIN2 codes (depending on the functionality being tested)
**Testing steps:**
1. Install the demo app using `./gradlew installDebug`
2. Enable NFC on your Android device (Settings → NFC and contactless payments)
3. Launch the demo app
4. Choose the desired operation (read card info, sign document, or authenticate)
5. Enter the required codes (CAN, PIN1, or PIN2) when prompted
6. Hold your ID card against the device's NFC antenna
7. Keep the card steady until the operation completes
> [!TIP]
> The exact location of the NFC antenna varies by device model. It's typically near the camera on the back of the phone.

### Using the Libraries in Other Applications

#### Building the AAR

```shell
./gradlew -p libs assemble
```

* The `.aar` files are located in:
  * `libs/id-card-lib/build/outputs/aar`
  * `libs/smart-card-reader-lib/build/outputs/aar`
  * `libs/card-utils-lib/build/outputs/aar`
* Move the resulting `.aar` files to your project's `/libs` directory.
* Add the dependencies to your application's `build.gradle` file, substituting
  `<version>` with the one in `version.properties`:
    * `implementation files('app/libs/id-card-lib-<version>-release.aar')`
    * `implementation files('app/libs/smart-card-reader-lib-<version>-release.aar')`
    * `implementation files('app/libs/card-utils-lib-<version>-release.aar')`

The filenames carry the library version and the build type — see
[Versioning the AAR](#versioning-the-aar) for where those come from and what to do
if you would rather drop them in under a stable name.

#### Versioning the AAR

The AAR name carries the library version, and optionally a suffix marking it as
somebody's own build. They come from two files, which differ in one important way.

**`version.properties`, at the repository root, is committed:**

```properties
# version.properties
version=2.0.0
```

This is the library version for all three AARs. It is in git on purpose — a
version is a fact about the source, so a version in a log or an AAR name maps back
to a commit, and bumping it is a reviewable change. Pre-release tags work:
`2.0.0-rc` is a valid version. The build fails if the file or the key is missing,
since that means it was deleted rather than never created.

**`environment.properties`, also at the root, is gitignored and optional:**

```properties
# environment.properties
version.suffix=internal
```

A template is checked in as `environment.properties.example`. Set it to keep your
own builds apart from a release, or when consumers need to pin an exact build; it
never lands in a release AAR by accident because it is never committed.

* without a suffix → `id-card-lib-<version>-release.aar`
* with one        → `id-card-lib-<version>-internal-release.aar`

The trailing `-release` is the build type, which AGP appends to every AAR it
writes — a debug build of the first line is `id-card-lib-<version>-debug.aar`. It is
not part of what these keys control, but it is part of the filename, and the
version the library reports about itself includes it for that reason.

**Every AAR is versioned, so there is no bare `id-card-lib.aar`.** Integrators have
two workable conventions and should pick one deliberately:

* **Keep the emitted name** and reference it as-is, as the snippets above do. The
  dependency line then states which build is in the app, and bumping the library is
  a visible one-line change.
* **Rename on drop-in** to a stable `id-card-lib.aar`. The dependency lines never
  change, but nothing in the consuming project records which build it holds — so
  ask the library instead, with `IdCardLibrary.version()`.

Both values become a filename and a Java string literal, so both are restricted to
letters, digits, dots, underscores and hyphens, with a hyphen between other
characters rather than at either end. Anything else — a slash, a space, a quote —
fails the build with a message naming the key that is wrong, rather than a javac
error in generated code.

This applies to every Android library subproject under `libs/` and is wired up in
`libs/build.gradle.kts`.

> [!NOTE]
> `version` and `suffix` used to live together in `environment.properties`. The
> version moved to `version.properties`, and `suffix` is now `version.suffix`. A
> leftover key of either old name is warned about at configuration time rather
> than silently ignored.

#### Reporting the Library Version

The same two values reach the code, so a build can say what it is:

```kotlin
IdCardLibrary.version()   // "2.0.0-internal-release", or "2.0.0-release" with no suffix
```

That is the AAR's own filename without the module and the extension —
`id-card-lib-2.0.0-internal-release.aar` reports `2.0.0-internal-release` — so a
version in a log and the artefact it came from cannot disagree. The tail is the
build type, named rather than inferred, so a `-debug` in a log is recognisable as
a build that was never shipped. Because the version is committed, every build
reports a real one; there is no "unknown" case.

The library also puts it on the card line it logs once per tap, so a captured
`logcat` identifies the library that produced it without anyone having to write
the version into the filename:

```
TokenWithPace: card: EE IDEMIA "SeID", ATS 0012233f536549440f9000 (ID1) -> IdemiaWithPace [id-card-lib 2.0.0-internal-release]
```

That line is subject to the same `loggingEnabled` gate as everything else below;
`IdCardLibrary.version()` is not, so an app can report the version in a crash
report or a diagnostics screen with logging off.

#### Integrator Dependencies

The three AARs are shipped as flat-file drop-ins (`implementation files(...)`),
which carries no Maven metadata, so transitive dependencies do **not** resolve
automatically. The integrator's `build.gradle.kts` must declare them explicitly:

```kotlin
dependencies {
    // The three AARs, named as the build emits them
    implementation(files("libs/id-card-lib-<version>-release.aar"))
    implementation(files("libs/smart-card-reader-lib-<version>-release.aar"))
    implementation(files("libs/card-utils-lib-<version>-release.aar"))

    // Referenced by id-card-lib + smart-card-reader-lib
    implementation("androidx.annotation:annotation:1.9.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    implementation("com.google.guava:guava:33.5.0-android")

    // Referenced by card-utils-lib (LoggingUtil + its Dagger-generated factory)
    implementation("javax.inject:javax.inject:1")
    implementation("com.google.dagger:dagger:2.57.2")
    implementation("com.google.dagger:hilt-core:2.57.2")
    // Only if the integrator also wants Hilt injection for LoggingUtil:
    // implementation("com.google.dagger:hilt-android:2.57.2")

    // Required for id-card-lib's java.time.* usage when minSdk < 26
    // (see next section)
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
}
```

> [!NOTE]
> AutoValue and the Hilt compiler are build-time only — the generated classes
> ship inside the AARs, so consumers do not need to add `auto-value`,
> `auto-value-annotations`, or `hilt-android-compiler`.

#### Minimum SDK and Core Library Desugaring

The libraries target **`minSdk = 24`** (Android 7.0).

Because `id-card-lib` uses `java.time.*` APIs (`LocalDate`, `Instant`,
`ZoneOffset`, etc.) which are not part of the Android platform until
API 26 (Android 8.0), the integrator app must enable **core library
desugaring** when its `minSdk` is below 26.

```kotlin
android {
    compileSdk = 36
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
}
```

For an app whose `minSdk` is already 26 or higher, the desugaring block can
be omitted — the platform provides `java.time.*` directly.

#### Debug Logging

`card-utils-lib` exposes `LoggingUtil.initialize(context, logger, loggingEnabled)`,
which the other library modules use to emit transport-level traces.

> [!WARNING]
> **Never enable `loggingEnabled = true` in a production build.** When set,
> the library writes raw APDU bytes, decrypted card payloads, secure-messaging
> session MAC values, and (for cert reads) post-decrypt certificate bytes to
> the Android system log. Anything with `READ_LOGS` permission — or a
> developer with `adb logcat` access — can recover this data. The logs are
> intended for protocol debugging during integration only.

Leave `loggingEnabled = false` (the default) in release builds. If you need
to capture a trace from a customer's device, gate the call behind a debug
build type or a runtime developer-options flag — do not toggle it in
production code paths.

## Overview

ID card support for Android applications is based on two libraries: `id-card-lib` and `smart-card-reader-lib`.

* `smart-card-reader-lib` enables the use of the ID card over NFC. It provides the NFC smart card reader interface and communication layer.
* `id-card-lib` implements the APDU-based communication protocols required to use the core functionality across different types of ID cards: Estonian IDEMIA, Estonian Thales, and Latvian IDEMIA.
Integrating ID card support into an Android application proceeds as follows:

* The developer declares the NFC permission in the application manifest.
* The developer creates an `NfcSmartCardReaderManager` instance.
* Using the manager, the developer detects the ID card and creates a card instance via `TokenWithPace.create()`.
* The developer establishes a secure communication channel between the card and the device using the card’s CAN code.
* The developer communicates with the card instance to use the desired functionalities—authentication, digital signing, etc.

An example of using the NFC interface can be found in the demo application: `CardReaderFragment.kt`. The example is written in Kotlin, but the library can also be used in Java applications. The sample app additionally depends on the `libdigidocpp` library, which enables the creation of signed ASiC-E containers; however, this dependency is not required for using the ID card via NFC. 

## NFC Interface

### General Communication Scheme

An application that wants to use the ID card via the NFC interface must declare the NFC permission in its manifest:

````xml
<uses-permission android:name="android.permission.NFC" />
````

Communication with the ID card takes place through the `android.nfc.tech.IsoDep` class using **NFC-A** technology.  
The Android NFC interface specifics are implemented by the library.

```kotlin
import ee.ria.DigiDoc.smartcardreader.nfc.NfcSmartCardReaderManager
...
private lateinit var nfcSmartCardReaderManager: NfcSmartCardReaderManager
...
nfcSmartCardReaderManager = NfcSmartCardReaderManager()
```

To communicate with the ID card, create an instance of the NFC manager  
`ee.ria.DigiDoc.smartcardreader.nfc.NfcSmartCardReaderManager` and use the methods provided by this class.

```java
public NfcStatus detectNfcStatus(Activity activity) {}
public NfcStatus startDiscovery(Activity activity, NfcSmartCardReaderCallback callback) {}
public void onTagDiscovered(Tag tag) {}
public void disableNfcReaderMode() {}
```

* The `detectNfcStatus` method can be used to determine whether the device supports NFC and whether NFC is enabled.  
* The `startDiscovery` method makes the specified `Activity` monitor the NFC interface. When an NFC tag with a compatible technology is detected, the `onTagDiscovered` **callback method** is invoked. This method is **not** implemented by the library integrator; instead, the integrator implements the `NfcSmartCardReaderCallback` interface, whose `onNfcReader` method receives either a ready-to-use NFC reader or an exception.  
* The `disableNfcReaderMode` method stops the application from further monitoring the NFC interface.

```java
public interface NfcSmartCardReaderCallback {
    void onNfcReader(NfcSmartCardReader reader, SmartCardReaderException ex);
}
```

The implementation of the `NfcSmartCardReaderCallback` interface is responsible for invoking ID card functionality and handling errors.

```java
public interface TokenWithPace extends Token {
    void tunnel(String can) throws SmartCardReaderException;
    static TokenWithPace create(NfcSmartCardReader reader, TokenWithPaceConfig config) throws SmartCardReaderException {
    }
}
```

The `TokenWithPace` interface enables NFC communication with the ID card. An instance is obtained via
its `create` factory method, which selects the correct implementation based on the card's ATS (*Answer To Select*)
and the `TokenWithPaceConfig` allow-list passed by the integrator.
Three NFC-enabled ID card types are currently supported:

| Card | Implementation |
|---|---|
| Estonian IDEMIA (ID1) | `IdemiaWithPace` |
| Estonian Thales | `ThalesWithPace` |
| Latvian IDEMIA | `LatviaIdemiaWithPace` (extends `IdemiaWithPace`) |

If the card's ATS does not match any of these, `create` throws a `NotSupportedException`
(see [Exception Handling](#exception-handling)).

After creating the instance, establish the communication channel using the card’s `CAN` code and the `tunnel` method.

```java
public interface Token {
    PersonalData personalData() throws SmartCardReaderException;
    int codeRetryCounter(CodeType type) throws SmartCardReaderException;
    byte[] certificate(CertificateType type) throws SmartCardReaderException;
    SignatureAlgorithm signatureAlgorithm(CertificateType type, byte[] certificate) throws SmartCardReaderException;
    Set<SignatureAlgorithm> permittedAlgorithms(CertificateType type, byte[] certificate) throws SmartCardReaderException;
    byte[] calculateSignature(byte[] pin2, byte[] hash, boolean ecc) throws SmartCardReaderException, CodeVerificationException;
    byte[] authenticate(byte[] pin1, byte[] token) throws SmartCardReaderException, CodeVerificationException;
    byte[] decrypt(byte[] pin1, byte[] data, boolean ecc) throws SmartCardReaderException, CodeVerificationException;
    void changeCode(CodeType type, byte[] currentCode, byte[] newCode) throws SmartCardReaderException, CodeVerificationException;
    void unblockAndChangeCode(byte[] pukCode, CodeType type, byte[] newCode) throws SmartCardReaderException, CodeVerificationException;
    int pinChangedFlag(CodeType type) throws SmartCardReaderException;
    CardType cardType();
}
```

If the tunnel is created successfully, ID card functionality becomes available over NFC.  

The functions are defined in the `Token` interface.  

> **Latvian cards read a little more from the card than Estonian ones.** For
> `LATVIA_IDEMIA`, the algorithm and key references used to sign are read from the
> card's own PKCS#15 metadata rather than assumed, because those values differ
> between Latvian personalisations that share an ATS — and in one case differ from
> the values the library would otherwise have sent. That costs a PKCS#15 walk
> — three files and the applet re-select, twelve APDUs — measured at 930–945 ms
> per operation, cached for the session. Estonian cards skip it and behave exactly
> as before. Neither needs anything from the caller.
>
> **What a key can sign with, as opposed to what it will.** `signatureAlgorithm(type, cert)` returns the one algorithm the library will use, and that is the one to name in a token or JWS header. `permittedAlgorithms(type, cert)` returns everything that key could sign with — usually just that one, since an EC key is fixed by its curve and an RSA key is fixed by the card whenever the card names a hash. More than one comes back only for an RSA key whose card names no hash: it signs whatever it is handed, so the PKCS#1 encoding built by this library is what fixes the algorithm, and RS256, RS384 and RS512 are equally valid. The library still uses RS256 there and requires a digest matching it — this is an answer about the card, not a setting. It shares the cache with `signatureAlgorithm`, so asking both costs no extra read.
>
> Unchanged in both cases: `calculateSignature` widens a digest shorter than the
> curve's field to that width, `authenticate` passes your bytes through as they
> are.

Below is an example of reading the personal data file from the ID card when an instance of `NfcSmartCardReaderManager` has already been created.

```kotlin
private val tokenConfig = TokenWithPaceConfig.Builder()
    .allow(CardType.ID1, CardType.THALES)
    .build()

private fun readCardData() {
    checkNfcStatus(nfcSmartCardReaderManager.startDiscovery(requireActivity()) { nfcReader, exc ->
        if ((nfcReader != null) && (exc == null)) {
            try {
                val card = TokenWithPace.create(nfcReader, tokenConfig)
                card.tunnel(dataViewModel.getCan())
                val cardData = card.personalData()
            } catch (ex: SmartCardReaderException) {
                ...
            } finally {
                nfcSmartCardReaderManager.disableNfcReaderMode()
            }
        }
    })
}
```

* **Lines 1–3:** Configure which card types the app accepts. The `TokenWithPaceConfig` is **required**; passing only the card types you actually support is recommended so that a future library release that adds another country/variant cannot silently widen the set of cards your app reads. To opt in to every supported type explicitly, use `TokenWithPaceConfig.allowAll()`.
* **Line 6:** Uses the `startDiscovery` method, which internally uses `android.nfc.NfcAdapter.enableReaderMode` to detect NFC tags. The returned `NfcStatus` value is processed.
* **Line 7:** The `startDiscovery` method relies on the `NfcSmartCardReaderCallback` interface; if no exception is present and an `NfcSmartCardReader` instance exists, processing continues.
* **Line 9:** Creates an instance implementing the `TokenWithPace` interface. The card's ATS historical bytes are matched against the library's supported set; if the detected `CardType` is not in `tokenConfig.allowedCardTypes()`, a `NotSupportedException` is thrown immediately (no PACE handshake is attempted).
* **Line 10:** Uses the card's `CAN` code to establish a secure NFC connection between the card and the device.
* **Line 11:** Uses ID card functionality to read the personal data file.
* **Line 12:** Any of the above operations may result in a `SmartCardReaderException`.
* **Line 15:** Stops waiting for NFC tags.

### NFC Interface Status

Depending on the Android device, the NFC interface may or may not be available.  
If present, it can be either enabled or disabled.  
These states are described by the `enum NfcStatus`, which is returned by the manager method `startDiscovery` but can also be detected using the `detectNfcStatus` method, allowing the application to respond accordingly.

```kotlin
private fun checkNfcStatus(status: NfcStatus) {
    when (status) {
        NfcStatus.NFC_NOT_SUPPORTED -> communicationTextView.text = getString(R.string.nfc_not_supported)
        NfcStatus.NFC_NOT_ACTIVE -> communicationTextView.text = getString(R.string.nfc_not_turned_on)
        NfcStatus.NFC_ACTIVE -> communicationTextView.text = getString(R.string.card_detect_info)
    }
}
```

* `NFC_NOT_SUPPORTED` – the device does not have an NFC interface.  
* `NFC_NOT_ACTIVE` – the device has an NFC interface, but it is turned off.  
* `NFC_ACTIVE` – the device has an active NFC interface.  

---

### Exception Handling

When communicating with the ID card via the NFC interface, various error situations may occur —  
at the NFC communication level, the APDU protocol level, or within card-specific functionalities.  
The following example demonstrates exception handling during the ID card communication process.

```kotlin
private fun exceptionHandler(ex: SmartCardReaderException) {
    if (ex is NotSupportedException) {
        ...
    } else if (ex is CertificateNotFoundException) {
        ...
    } else if (ex is CodeVerificationException) {
        ...
    } else if (ex is CodeFormatException) {
        ...
    } else if (ex is SignatureAlgorithmException) {
        ...
    } else if (ex is SecurityEnvironmentException) {
        ...
    } else if (ex is PaceTunnelException) {
        ...
    } else if (ex is IdCardException) {
        ...
    } else if (ex is ApduResponseException) {
        ...
    } else {
        if (ex.cause is TagLostException) {
            ...
        } else {
            ...
        }
    }
}
```

* **Line 1:** `ee.ria.DigiDoc.smartcardreader.SmartCardReaderException` – base exception from which all ID card–related exceptions inherit.
* **Line 2:** `ee.ria.DigiDoc.idcard.NotSupportedException` – thrown by `TokenWithPace.create(...)` when either:
  (a) the detected card's ATR/ATS does not match any supported model (e.g. attempting to read a non-Estonian / non-Latvian / non-Thales ID card), or
  (b) the detected `CardType` is not in the `TokenWithPaceConfig.allowedCardTypes()` passed to `create()` — for example, an integrator scoped to `{ID1, THALES}` will get this when tapping a `LATVIA_IDEMIA` card.
  Catch this case separately to show the user a "card not supported" message rather than a generic communication error.
* **Line 4:** `ee.ria.DigiDoc.idcard.CertificateNotFoundException` – thrown by `certificate(...)` when the card carries no certificate of the requested type.
  It is raised only after every known location has been tried and come back empty — each EF this card model keeps certificates in, and then whatever the card's own PKCS#15 directory names —
  so it is a statement about the card, not about the read: a failed tap surfaces as `ApduResponseException` or `TagLostException` instead.
  `certificateType()` says which certificate was requested, and the message lists every location searched with what each one held.
  Treat it as "this card cannot do this" — e.g. a card personalised without a signing certificate — rather than as something a retry will fix.
* **Line 6:** `ee.ria.DigiDoc.idcard.CodeVerificationException` – specific exception indicating that the PIN1 or PIN2 used for authorization was incorrect.
  The exception includes information on how many attempts remain before the PIN becomes locked.
* **Line 8:** `ee.ria.DigiDoc.idcard.CodeFormatException` – thrown before anything is sent to the card when a PIN or PUK is empty, or longer than the twelve-byte code field.
  Codes travel right-padded to twelve bytes, so an empty one would become twelve filler bytes: a well-formed command the card cannot tell apart from a real attempt, since the padding is applied host-side. On a verify that spends one of the user's retries; on a change or unblock the card **stores** those bytes, leaving a code no keypad can reproduce.
  Only the field's own limits are checked — minimum lengths are card policy and differ by model, so validate those in your own UI before calling.
* **Line 10:** `ee.ria.DigiDoc.idcard.SignatureAlgorithmException` – thrown by `signatureAlgorithm(...)` when the library cannot sign with that certificate's key, and by the signing calls when the hash does not suit the algorithm the card named.
  Ask `signatureAlgorithm(type, cert)` rather than deriving the algorithm from the certificate yourself: the name that goes in a JWS header or Web eID token and the algorithm reference the library puts in `MSE:SET` are two halves of one decision, and answering in one place is what keeps them in step. EC and RSA keys are both supported.
  It is also raised after an authentication when the signature the card produced does not verify under its own certificate — which means the algorithm or key reference the card described is not what it actually signed with. That check is skipped, not failed, when no certificate has been read in the session.
  It is raised before anything reaches the card in the first two cases, so those cost no PIN retry. For Latvian cards the algorithm and key references come from the card's own PKCS#15 metadata; Estonian cards use constants.
* **Line 12:** `ee.ria.DigiDoc.idcard.SecurityEnvironmentException` – thrown for Latvian cards when the card will not describe its own keys.
  Those cards' algorithm and key references differ between personalisations that share an ATS, so the library reads them from the card and refuses rather than assume — a wrong assumption is accepted by the card and produces a signature that verifies nowhere.
  Raised before any PIN is verified, so it costs no retry. Estonian cards never raise it: they use constants by design.
* **Line 14:** `ee.ria.DigiDoc.idcard.PaceTunnelException` – specific exception indicating that the establishment of a secure communication channel between the card and the device has failed.
  Most likely, the issue is caused by an incorrect CAN code.
* **Line 16:** `ee.ria.DigiDoc.idcard.IdCardException` – general exception class for ID card-specific errors that don't fall into other categories.
* **Line 18:** `ee.ria.DigiDoc.smartcardreader.ApduResponseException` – exception indicating an error in the ID card's APDU communication protocol.
* **Line 21:** `android.nfc.TagLostException` – exception indicating that the NFC connection between the card and the device was lost.
* **Line 23:** Any other unexpected exception that triggered the `SmartCardReaderException`.   

---

### Specifics of the NFC Interface

The NFC interface has certain characteristics that require attention in the application UI and communication flow.

1. The user must know the NFC antenna’s location on the device and physically hold the card against it.  
   This is often inconvenient and unstable.  
   Additionally, the card cannot be accessed before a secure channel is established using the correct CAN code —  
   for example, it is not possible to read PIN retry counters or display warnings to the user beforehand.  
   While the user is holding the card near the NFC interface, it can be difficult to operate the device otherwise (e.g., to enter PIN or CAN codes).

2. Over NFC, the APDU protocol is **encrypted and authenticated** using Secure Messaging.  
   The card may also enforce additional restrictions — not all functionalities are available over NFC.

3. The **CAN** is a six-digit, card-specific number required to establish the PACE tunnel over NFC.  
   Unlike PIN codes, the CAN cannot be changed or locked.  
   As a protection mechanism against brute-force attempts, IDEMIA cards introduce a delay:  
   after 10 consecutive incorrect CAN entries, the card enforces a **30-second delay** before the next CAN validation.  
   Once the correct CAN is entered, normal operation resumes immediately.
