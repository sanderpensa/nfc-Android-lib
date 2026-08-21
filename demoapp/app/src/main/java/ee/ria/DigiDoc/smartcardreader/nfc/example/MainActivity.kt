/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package ee.ria.DigiDoc.smartcardreader.nfc.example

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.system.ErrnoException
import android.system.Os
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.NavController
import androidx.navigation.fragment.NavHostFragment
import ee.ria.DigiDoc.idcard.IdCardLibrary
import ee.ria.DigiDoc.smartcardreader.nfc.NfcSmartCardReaderManager
import ee.ria.DigiDoc.smartcardreader.nfc.example.configuration.ContainerConfiguration
import ee.ria.DigiDoc.smartcardreader.nfc.example.databinding.ActivityMainBinding
import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil.Companion.errorLog
import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil.Companion.infoLog
import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil.Companion.initialize
import ee.ria.libdigidocpp.Conf
import ee.ria.libdigidocpp.DigiDocConf
import ee.ria.libdigidocpp.DigiDocWrapperImpl
import ee.ria.libdigidocpp.digidoc
import java.util.Locale
import java.util.logging.Logger

class MainActivity : AppCompatActivity() {
    private val logTag = javaClass.simpleName
    private lateinit var navigationController: NavController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Debug builds only, and deliberately so — this is the line an integrator
        // copies. Enabling it turns on the library's APDU logging *and* this app's
        // own diagnostic lines, and one of those (see CardReaderFragment) writes the
        // authentication certificate to the system log. An eID certificate carries
        // the holder's name and personal code, so a release build that left this on
        // would publish citizen data from every device it ran on, to anything able
        // to read the log.
        //
        // The library itself is quieter than that — post-PACE APDUs are logged as
        // ciphertext and responses only by status word — so what this really gates
        // is the diagnostics around it. That is exactly why it should be off by
        // default rather than switched off later.
        initialize(
            this, Logger.getLogger(
                NfcSmartCardReaderManager::class.java.name
            ), BuildConfig.DEBUG
        )

        // What an integrator does with IdCardLibrary.version(): report which build
        // of the library is in the app. Logged here as the first thing after
        // logging is on, so a capture that starts with the app has it; the library
        // repeats it on every card line, so a capture that starts later does too.
        // Equally suited to a crash report or an about screen — it reads a
        // compile-time constant and touches no card.
        infoLog(logTag, "id-card-lib ${IdCardLibrary.version()}")

        // install schema files
        val digidocWrapperImpl = DigiDocWrapperImpl(this)
        digidocWrapperImpl.install()

        // container configuration
        initLibDigiDocConfiguration(digidocWrapperImpl.schemaDirectory())

        val navHostFragment =
            supportFragmentManager.findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        navigationController = navHostFragment.navController

    }

    private fun initLibDigiDocConfiguration(schemaAbsolutePath: String) {

        try {
            Os.setenv("HOME", schemaAbsolutePath, true)
        } catch (ex: ErrnoException) {
            ex.printStackTrace()
            errorLog(logTag, "Setting HOME environment variable failed", ex)
        }
        val digiDocConf = DigiDocConf(schemaAbsolutePath)
        Conf.init(digiDocConf.transfer())

        val conf = ContainerConfiguration()
        conf.increaseLogLevel()
        conf.setupTSLFiles(schemaAbsolutePath)
        conf.overrideTSLUrl()
        conf.overrideTSLCert()
        conf.initTsaUrl()

        digidoc.initializeLib(getUserAgent(), schemaAbsolutePath)
    }

    private fun getUserAgent(): String {
        val message = StringBuilder()
        message.append("nfxexample/").append(getAppVersion(this))
        message.append(" (Android ").append(Build.VERSION.RELEASE).append(")")
        message.append(" Lang: ").append(Locale.getDefault().language)
        return message.toString()
    }

    private fun getAppVersion(context: Context): StringBuilder {
        val versionName = StringBuilder()
        try {
            versionName.append(
                context.packageManager.getPackageInfo(
                    context.packageName,
                    0
                ).versionName
            )
                .append(".")

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                versionName.append(
                    context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode
                )
            } else {
                @Suppress("DEPRECATION")
                versionName.append(
                    context.packageManager.getPackageInfo(context.packageName, 0).versionCode
                )
            }
        } catch (e: PackageManager.NameNotFoundException) {
            e.printStackTrace()
        }
        return versionName
    }
}