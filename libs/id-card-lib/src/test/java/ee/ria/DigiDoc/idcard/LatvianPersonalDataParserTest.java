package ee.ria.DigiDoc.idcard;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import ee.ria.DigiDoc.smartcardreader.SmartCardReaderException;

/**
 * The parser on its own, without a card.
 *
 * <p>{@link LatviaIdemiaPersonalDataTest} covers the same parsing end to end through
 * a mocked reader — the record decoding included — which is what proves the token
 * wires the two together. This covers what a mocked card makes awkward: bytes that
 * are not a certificate at all.
 */
public final class LatvianPersonalDataParserTest {

    /** Not a certificate. The message names which read failed, not the bytes. */
    @Test
    public void certificateThatIsNotDer_failsAsACardError() {
        byte[] record = "150385-12345".getBytes(StandardCharsets.UTF_8);
        byte[] notACertificate = {0x01, 0x02, 0x03, 0x04};

        SmartCardReaderException thrown = assertThrows(SmartCardReaderException.class,
                () -> LatvianPersonalDataParser.parse(record, notACertificate));

        assertThat(thrown).hasMessageThat().contains("auth certificate");
    }
}
