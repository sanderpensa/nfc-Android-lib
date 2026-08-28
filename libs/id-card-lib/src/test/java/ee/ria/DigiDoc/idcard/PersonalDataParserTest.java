package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import android.util.SparseArray;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;

/**
 * The eight personal-data records, for the card models that state them in files.
 *
 * <p>The replay tests cover each model end to end against captured traffic; this
 * covers what those captures do not contain — records a card left blank, and codes
 * that encode no date.
 */
public final class PersonalDataParserTest {

    /** Eight records of a plausible card, the varying ones left to the caller. */
    private static SparseArray<String> records(String citizenship, String dateAndPlace) {
        SparseArray<String> data = new SparseArray<>();
        data.put(1, "TESTNUMBER");
        data.put(2, "TESTNAME");
        data.put(3, "M");
        data.put(4, citizenship);
        data.put(5, dateAndPlace);
        data.put(6, "38001085718");
        data.put(7, "ES0250124");
        data.put(8, "12 08 2030");
        return data;
    }

    /**
     * IDEMIA states the place of birth after the date, Thales the date alone. Both
     * give the same date, which is why one parser serves both.
     */
    @Test
    public void dateOfBirth_readsPastAnyPlaceOfBirth() throws SmartCardReaderException {
        assertThat(PersonalDataParser.parse(records("EST", "08 01 1980 FIN"), CardType.ID1)
                .dateOfBirth()).isEqualTo(LocalDate.of(1980, 1, 8));
        assertThat(PersonalDataParser.parse(records("EST", "23 10 1989"), CardType.THALES)
                .dateOfBirth()).isEqualTo(LocalDate.of(1989, 10, 23));
    }

    /** The model is the caller's to state; nothing else here varies by card. */
    @Test
    public void cardType_isTheOneTheCallerNamed() throws SmartCardReaderException {
        assertThat(PersonalDataParser.parse(records("EST", "08 01 1980 FIN"), CardType.ID1)
                .cardType()).isEqualTo(CardType.ID1);
        assertThat(PersonalDataParser.parse(records("EST", "23 10 1989"), CardType.THALES)
                .cardType()).isEqualTo(CardType.THALES);
    }

    @Test
    public void blankCitizenshipRecord_isNull() throws SmartCardReaderException {
        assertThat(PersonalDataParser.parse(records("", "08 01 1980 FIN"), CardType.ID1)
                .citizenship()).isNull();
    }

    @Test
    public void statedCitizenship_survives() throws SmartCardReaderException {
        assertThat(PersonalDataParser.parse(records("EST", "08 01 1980 FIN"), CardType.ID1)
                .citizenship()).isEqualTo("EST");
    }

    /**
     * A card that states no personal code and no date of birth fails the read, and
     * fails it as the checked exception {@code personalData()} declares.
     *
     * <p>The type is the point: an unusable file is a fact about the card, so it
     * travels the same channel as a status word refusing a read.
     */
    @Test
    public void noPersonalCodeAndNoDateOfBirth_failsAsACardError() {
        SparseArray<String> data = records("EST", "");
        data.put(6, "");

        assertThrows(SmartCardReaderException.class,
                () -> PersonalDataParser.parse(data, CardType.ID1));
    }

    /**
     * A personal code that encodes no date of birth costs that one field, not the
     * whole read.
     *
     * <p>The leading 9 names no century, so {@link EstonianPersonalCode} has no date
     * to give. Everything the card did state comes back.
     */
    @Test
    public void personalCodeEncodingNoDateOfBirth_keepsTheRestOfTheData()
            throws SmartCardReaderException {
        SparseArray<String> data = records("EST", "");
        data.put(6, "98001085718");

        PersonalData pd = PersonalDataParser.parse(data, CardType.ID1);

        assertThat(pd.dateOfBirth()).isNull();
        assertThat(pd.surname()).isEqualTo("TESTNUMBER");
        assertThat(pd.documentNumber()).isEqualTo("ES0250124");
    }

    /**
     * A record 5 the card garbled does not cost the date, because the personal code
     * encodes one too. The two are a ladder, not a choice.
     */
    @Test
    public void unparseableDateRecord_fallsBackToThePersonalCode()
            throws SmartCardReaderException {
        PersonalData pd = PersonalDataParser.parse(
                records("EST", "08 01 8O FIN"), CardType.ID1);

        assertThat(pd.dateOfBirth()).isEqualTo(LocalDate.of(1980, 1, 8));
    }

    /** With both sources unusable the field is absent, and the read still succeeds. */
    @Test
    public void neitherSourceUsable_leavesOnlyTheDateAbsent() throws SmartCardReaderException {
        SparseArray<String> data = records("EST", "08 01 8O FIN");
        data.put(6, "98001085718");

        PersonalData pd = PersonalDataParser.parse(data, CardType.ID1);

        assertThat(pd.dateOfBirth()).isNull();
        assertThat(pd.surname()).isEqualTo("TESTNUMBER");
    }
}
