import java.util.Properties

fun loadProperties(file: File): Properties {
    val properties = Properties()
    if (file.exists()) {
        file.inputStream().use { properties.load(it) }
    }
    return properties
}

/**
 * Rejects a value that cannot safely become both a filename and a Java string
 * literal, which is what the version and its suffix are used for.
 *
 * <p>Checked rather than escaped. A value holding a quote or a backslash would
 * otherwise generate a `BuildConfig.java` that does not compile, and the error
 * would point at generated code instead of at the setting that caused it — while a
 * slash or a space would produce an AAR name nobody meant.
 *
 * <p>A hyphen has to sit between other characters, because it is also the
 * separator these values are joined with: a suffix of `-sl` would otherwise read
 * back as `1.2.7--sl`, an empty segment in both the AAR name and the reported
 * version. Hyphens inside a value are fine, so `1.2.7-rc` is a valid version.
 *
 * <p>Trimmed first: Properties keeps trailing whitespace, so `version.suffix=sl `
 * — a typo that looks like nothing in an editor — would otherwise fail the build.
 * Surrounding space is never meaningful in a filename or a version.
 */
fun checkedProperty(file: String, key: String, value: String?): String? {
    val trimmed = value?.trim()
    if (trimmed.isNullOrEmpty()) {
        return null
    }
    require(trimmed.matches(Regex("[A-Za-z0-9._]+(?:-[A-Za-z0-9._]+)*"))) {
        "$file: `$key` is \"$trimmed\", which cannot be used in an AAR name or in" +
            " generated source. Use letters, digits, dot, underscore or hyphen, with" +
            " a hyphen between other characters rather than at either end."
    }
    return trimmed
}

// The version is committed, so it is the same for everyone building this commit
// and a version in a log maps back to it. Missing means the file was deleted
// rather than never created, which is worth failing on.
val versionFile = rootProject.file("version.properties")
val libVersion: String = checkedProperty(
    "version.properties", "version", loadProperties(versionFile).getProperty("version"),
) ?: error(
    "version.properties is missing or has no `version`. It is committed and holds the" +
        " library version for all three AARs; restore it from git rather than" +
        " recreating it, so the version still matches the commit. Looked in:" +
        " ${versionFile.absolutePath}",
)

// A version starts with a digit — 1.2.7, not v1.2.7. Checked here rather than in
// checkedProperty because it is true of the version and not of the suffix, which is
// a word: `internal`, `rc`, someone's initials. IdCardLibraryVersionTest asserts the
// same thing about the reported version, so a rule that let `v1.2.7` build would
// build something the test suite then rejects.
require(libVersion.first().isDigit()) {
    "version.properties: `version` is \"$libVersion\", which does not start with a" +
        " digit. Use 1.2.7 rather than v1.2.7; a pre-release tag goes on the end," +
        " as in 1.2.7-rc."
}

// The suffix is local and optional — it marks a build as somebody's own. Not
// committed, so it never lands in a release AAR by accident.
val envFile = rootProject.file("environment.properties")
val envProps = loadProperties(envFile)
val libSuffix: String? =
    checkedProperty("environment.properties", "version.suffix", envProps.getProperty("version.suffix"))

// These two moved. Warned about rather than ignored, because environment.properties
// is gitignored: a stale key would otherwise sit there looking effective while the
// build quietly used something else.
listOf(
    "version" to "the version now lives in version.properties, which is committed",
    "suffix" to "renamed to `version.suffix`",
).forEach { (staleKey, advice) ->
    if (envProps.getProperty(staleKey) != null) {
        logger.warn("environment.properties: `$staleKey` is no longer read — $advice.")
    }
}

/**
 * The version and suffix as one string, e.g. `1.2.7-internal` — the AAR name
 * without the module, and the part of the reported version a build can know at
 * compile time. The `-debug`/`-release` tail comes from `BuildConfig.BUILD_TYPE`,
 * which AGP generates per variant, so it is not composed here.
 */
val libVersionName: String = listOfNotNull(libVersion, libSuffix).joinToString("-")

subprojects {
    // Read by the module that exposes a version — see id-card-lib's own script.
    // Composed here, next to the AAR name built from the same values, so the two
    // cannot be derived differently. Set outside the plugin callback so it is in
    // place before any module script is evaluated.
    extra["libVersionName"] = libVersionName

    pluginManager.withPlugin("com.android.library") {
        project.extensions.configure<BasePluginExtension>("base") {
            archivesName.set("${project.name}-$libVersionName")
        }
    }
}
