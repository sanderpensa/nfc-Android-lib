package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;

/**
 * Pins the {@link PersonalData} schema: every accessor returns what
 * {@link PersonalData#create} was given. Catches accidental field
 * renames or argument-order changes in the factory.
 */
public final class PersonalDataTest {

    @Test
    public void create_preservesAllFields() {
        LocalDate dob = LocalDate.of(1985, 3, 15);
        LocalDate doc = LocalDate.of(2030, 5, 1);
        PersonalData pd = PersonalData.create(
                "Tamm", "Mari", "EST",
                dob, "48503150000", "AB1234567",
                doc, CardType.LATVIA_IDEMIA);

        assertThat(pd.surname()).isEqualTo("Tamm");
        assertThat(pd.givenNames()).isEqualTo("Mari");
        assertThat(pd.citizenship()).isEqualTo("EST");
        assertThat(pd.dateOfBirth()).isEqualTo(dob);
        assertThat(pd.personalCode()).isEqualTo("48503150000");
        assertThat(pd.documentNumber()).isEqualTo("AB1234567");
        assertThat(pd.documentExpiryDate()).isEqualTo(doc);
        assertThat(pd.cardType()).isEqualTo(CardType.LATVIA_IDEMIA);
    }

    /**
     * Every field a card may decline to state is nullable, and null is what
     * "did not state it" looks like.
     *
     * <p>Citizenship is the one worth pinning: Latvian cards do not expose it over
     * NFC, and null is how that is said. An empty string would read as "the card
     * said nothing" — a different claim, and not the true one.
     */
    @Test
    public void create_acceptsNullableFieldsAsNull() {
        PersonalData pd = PersonalData.create(
                "X", "Y", /*citizenship*/ null,
                /*dateOfBirth*/ null, "00000000000", "XX000000",
                /*documentExpiryDate*/ null,
                CardType.LATVIA_IDEMIA);

        assertThat(pd.citizenship()).isNull();
        assertThat(pd.dateOfBirth()).isNull();
        assertThat(pd.documentExpiryDate()).isNull();
    }

    /** The Estonian shape: a document expiry, and a citizenship the card states. */
    @Test
    public void create_estonianCardStatesCitizenshipAndDocumentExpiry() {
        PersonalData pd = PersonalData.create(
                "X", "Y", "EST",
                LocalDate.of(1990, 1, 1), "00000000000", "XX000000",
                LocalDate.of(2030, 1, 1), CardType.ID1);

        assertThat(pd.citizenship()).isEqualTo("EST");
        assertThat(pd.documentExpiryDate()).isEqualTo(LocalDate.of(2030, 1, 1));
    }
}
