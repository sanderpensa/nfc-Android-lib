package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import android.util.SparseArray;

import org.junit.jupiter.api.Test;

/**
 * What the Estonian and Thales parsers do with a record the card left blank.
 *
 * <p>Both read the same eight fixed EF records and both always get eight strings
 * back, so "the card stated nothing here" arrives as an empty string and has to be
 * turned into the null {@link PersonalData} promises. The replay tests cover cards
 * that do state a citizenship; this covers the ones that do not, which no captured
 * transcript has.
 */
public final class PersonalDataParserTest {

    /** Eight records of a plausible EE card, citizenship left to the caller. */
    private static SparseArray<String> records(String citizenship) {
        SparseArray<String> data = new SparseArray<>();
        data.put(1, "TESTNUMBER");
        data.put(2, "TESTNAME");
        data.put(3, "M");
        data.put(4, citizenship);
        data.put(5, "08 01 1980 EST");
        data.put(6, "38001085718");
        data.put(7, "ES0250124");
        data.put(8, "12 08 2030");
        return data;
    }

    @Test
    public void idemia_blankCitizenshipRecord_isNull() {
        assertThat(IdemiaPersonalDataParser.parse(records("")).citizenship()).isNull();
    }

    @Test
    public void idemia_statedCitizenship_survives() {
        assertThat(IdemiaPersonalDataParser.parse(records("EST")).citizenship())
                .isEqualTo("EST");
    }

    @Test
    public void thales_blankCitizenshipRecord_isNull() {
        assertThat(ThalesPersonalDataParser.parse(records("")).citizenship()).isNull();
    }

    @Test
    public void thales_statedCitizenship_survives() {
        assertThat(ThalesPersonalDataParser.parse(records("EST")).citizenship())
                .isEqualTo("EST");
    }
}
