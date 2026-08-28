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

import java.time.LocalDate;

import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil;

/**
 * The date of birth an Estonian personal code encodes: a century digit, then
 * {@code YYMMDD}. See {@link LatvianPersonalCode} for the Latvian format, which
 * orders the same information differently.
 */
class EstonianPersonalCode {
    private static final String TAG = EstonianPersonalCode.class.getName();

    private EstonianPersonalCode() {}

    /**
     * The encoded date, or null for a code that encodes none.
     *
     * <p>Null rather than thrown, as {@link LatvianPersonalCode#parseDateOfBirth}
     * answers: a code that names no century, or no real date, is a fact about the
     * card, and the field it feeds is nullable.
     */
    static LocalDate parseDateOfBirth(String personalCode) {
        if (personalCode == null || personalCode.length() < 7) {
            return tooShort(personalCode);
        }

        int century;
        switch (Character.getNumericValue(personalCode.charAt(0))) {
            case 1, 2 -> century = 1800;
            case 3, 4 -> century = 1900;
            case 5, 6 -> century = 2000;
            case 7, 8 -> century = 2100;
            default -> {
                LoggingUtil.Companion.errorLog(TAG,
                        "Personal code names no century, so encodes no date of birth", null);
                return null;
            }
        }

        try {
            int year = Integer.parseInt(personalCode.substring(1, 3)) + century;
            int month = Integer.parseInt(personalCode.substring(3, 5));
            int day = Integer.parseInt(personalCode.substring(5, 7));

            return LocalDate.of(year, month, day);
        } catch (Exception e) {
            // Non-numeric digits, or a date no calendar has. LocalDate.of rejects
            // month 13 rather than rolling it into the next year. The class name
            // rather than the throwable: these messages quote the text they failed
            // on, which here is part of the personal code.
            LoggingUtil.Companion.errorLog(TAG, String.format(
                    "Could not parse date of birth (%s)", e.getClass().getSimpleName()), null);
            return null;
        }
    }

    private static LocalDate tooShort(String personalCode) {
        LoggingUtil.Companion.errorLog(TAG, String.format(
                "Personal code is too short to encode a date of birth (%d characters)",
                personalCode == null ? 0 : personalCode.length()), null);
        return null;
    }
}
