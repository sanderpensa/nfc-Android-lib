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

package ee.ria.DigiDoc.idcard;

/**
 * What this library is, for anything that has to report it.
 */
public final class IdCardLibrary {

    private IdCardLibrary() {}

    /**
     * The version of this library, as {@code 2.0.0-internal-release}.
     *
     * <p>Two parts or three, depending on whether a suffix is set, and together
     * they are the AAR's own filename without the module and the extension:
     * {@code id-card-lib-2.0.0-internal-release.aar} reports
     * {@code 2.0.0-internal-release}, and a build with no suffix reports
     * {@code 2.0.0-release}. The version comes from the committed
     * {@code version.properties} and the optional suffix from a local
     * {@code environment.properties}, the same two that name the file; the tail is
     * the build type, which is what AGP appends to the file. So a version in a log
     * and the artefact it came from cannot disagree.
     *
     * <p>The build type is named rather than inferred from a debug flag. Releases
     * are what ship, so {@code -release} is what will almost always be seen, and
     * that is the point of printing it: a log that says {@code -debug} is a log
     * from a build nobody shipped, and one that says something else again — a
     * build type added later — says that honestly instead of rounding it to
     * "release".
     *
     * <p>There is no "unknown" case: the version is committed, so every build of
     * every checkout reports a real one.
     *
     * <p>Logged once per tap as part of the card line, so a capture identifies the
     * library that produced it without anyone having to name it. Public so an app
     * can report it too — in a crash report, a diagnostics screen, or its own
     * startup banner.
     *
     * @return The version, never {@code null} and never empty.
     */
    public static String version() {
        return BuildConfig.LIB_VERSION + "-" + BuildConfig.BUILD_TYPE;
    }
}
