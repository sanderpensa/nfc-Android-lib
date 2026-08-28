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

import android.util.SparseArray;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;
import ee.ria.DigiDoc.utilsLib.logging.LoggingUtil;

/**
 * The eight personal-data records, for every card model that states them in files.
 *
 * <p>The record numbers below are the layout as the card states it, kept whole rather
 * than only where something reads them — record 3 is the cardholder's sex, which no
 * field of {@link PersonalData} carries, so it is read off the card and dropped.
 *
 * <p>IDEMIA and Thales cards use the same layout and differ only in what they put
 * after the date of birth: IDEMIA appends the place ({@code 08 01 1980 FIN}), Thales
 * states the date alone ({@code 23 10 1989}). The date is the first ten characters
 * either way, so the model is carried as a parameter and nothing else here varies by
 * card.
 *
 * <p>Latvian cards do not come through here at all: they state only the personal code
 * in a file and take the rest from the authentication certificate, which is why
 * {@link LatvianPersonalDataParser} exists alongside this. Nothing is shared between
 * the two — different sources, different shapes.
 */
final class PersonalDataParser {
    private static final String TAG = PersonalDataParser.class.getName();
    private static final DateTimeFormatter DATE_FORMAT = new DateTimeFormatterBuilder()
            .appendPattern("dd MM yyyy")
            .toFormatter();

    /** {@code dd MM yyyy} — what the date occupies, before any place of birth. */
    private static final int DATE_LENGTH = 10;

    private static final int SURNAME_POS = 1;
    private static final int GIVEN_NAMES_POS = 2;
    private static final int GENDER_POS = 3;
    private static final int CITIZENSHIP_POS = 4;
    private static final int DATE_AND_PLACE_OF_BIRTH_POS = 5;
    private static final int PERSONAL_CODE_POS = 6;
    private static final int DOCUMENT_NUMBER_POS = 7;
    private static final int EXPIRY_DATE_POS = 8;

    private PersonalDataParser() {
    }

    static PersonalData parse(SparseArray<String> data, CardType cardType)
            throws SmartCardReaderException {
        String surname = data.get(SURNAME_POS);
        String givenNames = data.get(GIVEN_NAMES_POS);
        // Blank means the card stated none — see PersonalData.citizenship().
        String citizenshipRecord = data.get(CITIZENSHIP_POS);
        String citizenship = citizenshipRecord.isEmpty() ? null : citizenshipRecord;
        String dateAndPlaceOfBirthString = data.get(DATE_AND_PLACE_OF_BIRTH_POS);
        String personalCode = data.get(PERSONAL_CODE_POS);
        String documentNumber = data.get(DOCUMENT_NUMBER_POS);
        String expiryDateString = data.get(EXPIRY_DATE_POS);

        if (dateAndPlaceOfBirthString.isEmpty() && personalCode.isEmpty()) {
            throw new SmartCardReaderException("Personal code not found");
        }

        // Two sources, tried in order rather than chosen between: the card states a
        // date of birth in record 5, and encodes one in the personal code. A record 5
        // that will not parse leaves nothing to defer to, so the code is asked next —
        // it is not a second opinion on a value the card gave, it is the only one
        // left.
        LocalDate dateOfBirth = parseDateOfBirth(dateAndPlaceOfBirthString);
        if (dateOfBirth == null) {
            dateOfBirth = EstonianPersonalCode.parseDateOfBirth(personalCode);
        }

        LocalDate expiryDate = parseExpiryDate(expiryDateString);

        return PersonalData.create(surname, givenNames, citizenship, dateOfBirth,
                personalCode, documentNumber, expiryDate, cardType);
    }

    private static LocalDate parseExpiryDate(String expiryDateString) {
        try {
            return LocalDate.parse(expiryDateString, DATE_FORMAT);
        } catch (Exception e) {
            // The value is logged here and withheld in parseDateOfBirth below: an
            // expiry date is not identifying on its own, a date of birth is.
            LoggingUtil.Companion.errorLog(TAG, String.format("Could not parse expiry date %s", expiryDateString), e);
            return null;
        }
    }

    private static LocalDate parseDateOfBirth(String dateAndPlaceOfBirthString) {
        if (dateAndPlaceOfBirthString.isEmpty()) {
            return null;
        }
        try {
            String dateOfBirthString = dateAndPlaceOfBirthString.substring(0, DATE_LENGTH);

            return LocalDate.parse(dateOfBirthString, DATE_FORMAT);
        } catch (Exception e) {
            // The record itself stays out: a date and place of birth are the
            // cardholder's. Not the throwable either — a parse failure names the text
            // it could not parse, so passing it would put the record back in by the
            // other door. Its class and the record's length are what triage needs.
            LoggingUtil.Companion.errorLog(TAG, String.format(
                    "Could not parse date of birth (%d characters, %s)",
                    dateAndPlaceOfBirthString.length(), e.getClass().getSimpleName()), null);
            return null;
        }
    }
}
