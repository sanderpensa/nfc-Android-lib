package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;

/**
 * The shape of the version the library reports about itself.
 *
 * <p>Shape rather than value. {@code version()} concatenates two
 * {@code BuildConfig} constants, so javac folds it to a single literal — asserting
 * that it equals itself, or that it is stable across calls, is a tautology about
 * that literal.
 *
 * <p>The value is composed in {@code libs/build.gradle.kts} from the committed
 * {@code version.properties} and the local, optional {@code environment.properties}
 * — see the README, "Versioning the AAR". The version half is the same for anyone
 * building this commit, so it can be asserted here; the suffix half is whatever a
 * developer set, so it cannot.
 */
public final class IdCardLibraryVersionTest {

    /**
     * Pins the separator, the order and the fact that a build type is named at all
     * — change any of those and a documented public format changes with it.
     *
     * <p>Compared against {@code BuildConfig.BUILD_TYPE} rather than a literal,
     * because {@code test} runs this under both variants: {@code testReleaseUnitTest}
     * exists alongside {@code testDebugUnitTest}, so a hard-coded {@code -debug}
     * passes on one and fails on the other. Reading the build type here also means a
     * build type added later needs no change.
     */
    @Test
    public void version_endsWithTheBuildType() {
        assertThat(IdCardLibrary.version()).endsWith("-" + BuildConfig.BUILD_TYPE);
    }

    /**
     * The version is committed, so every checkout reports a real one and this can
     * be asserted without knowing which. It would have failed against the earlier
     * arrangement, where a clean checkout composed {@code dev} because the version
     * lived in a gitignored file.
     */
    @Test
    public void version_startsWithTheCommittedVersionNumber() {
        assertThat(IdCardLibrary.version()).matches("\\d[A-Za-z0-9._-]*");
    }
}
