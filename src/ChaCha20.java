import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// https://datatracker.ietf.org/doc/html/rfc7539
public class ChaCha20 {

    private static final int[] SIGMA = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"
    private static final int STATE_SIZE = 16; // 16 слов по 4 байта

    private static final int[] state = new int[STATE_SIZE]; // состояние 16 x 32-бит
    private static final byte[] keyStream = new byte[64];   // выходной поток байтов (64 байта)
    private static int keyStreamIndex = 0;

    public static byte[] chaCha20Encrypt(byte[] key, int counter, byte[] nonce, byte[] plaintext) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Ключ должен быть длиной 32 байта");
        }
        if (nonce.length != 12) {
            throw new IllegalArgumentException("Одноразовый номер должен быть длиной 12 байт");
        }


        byte[] ciphertext = new byte[plaintext.length];
        int numBlocks = plaintext.length / 64;

        // Обработка полных блоков по 64 байта
        for (int j = 0; j < numBlocks; j++) {
            chaChaBlock(key, counter + j, nonce);
            for (int i = 0; i < 64; i++) {
                ciphertext[j * 64 + i] = (byte) (plaintext[j * 64 + i] ^ keyStream[i]);
            }
        }

        // Обработка остатка данных, если длина не кратна 64
        int remaining = plaintext.length % 64;
        if (remaining > 0) {
            ;
            chaChaBlock(key, counter + numBlocks, nonce);
            for (int i = 0; i < remaining; i++) {
                ciphertext[numBlocks * 64 + i] = (byte) (plaintext[numBlocks * 64 + i] ^ keyStream[i]);
            }
        }
        return ciphertext;
    }

    // Преобразование byte в int
    private static int bytesToInt(byte[] input, int offset) {
        return ByteBuffer.wrap(input, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static void initialization(byte[] key, int counter, byte[] nonce) {
        // Инициализация состояния
        state[0] = SIGMA[0];
        state[1] = SIGMA[1];
        state[2] = SIGMA[2];
        state[3] = SIGMA[3];

        // Ключ
        for (int i = 0; i < 8; i++) {
            state[4 + i] = bytesToInt(key, i * 4);
        }

        // Счётчик
        state[12] = counter;

        // Nonce
        state[13] = bytesToInt(nonce, 0);
        state[14] = bytesToInt(nonce, 4);
        state[15] = bytesToInt(nonce, 8);
    }

    // Четырёхугольное преобразование
    private static void quarterRound(int a, int b, int c, int d) {
        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);

        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 12);

        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 8);

        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 7);
    }

    private static void innerBlock() {
        // Столбцы
        quarterRound(0, 4, 8, 12);
        quarterRound(1, 5, 9, 13);
        quarterRound(2, 6, 10, 14);
        quarterRound(3, 7, 11, 15);

        // Диагонали
        quarterRound(0, 5, 10, 15);
        quarterRound(1, 6, 11, 12);
        quarterRound(2, 7, 8, 13);
        quarterRound(3, 4, 9, 14);
    }

    // 20 раундов преобразований
    private static void chaChaBlock(byte[] key, int counter, byte[] nonce) {
        initialization(key, counter, nonce);
        print(state);
        int[] workingState = Arrays.copyOf(state, STATE_SIZE);

        // 10 итераций по 2 раунда (всего 20 раундов)
        for (int i = 0; i < 10; i++) {
            innerBlock();
        }

        // Итоговое состояние
        for (int i = 0; i < STATE_SIZE; i++) {
            workingState[i] += state[i];
        }

        print(workingState);

        // Преобразование результата в поток байтов
        for (int i = 0; i < STATE_SIZE; i++) {
            ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(workingState[i]);
            System.arraycopy(buffer.array(), 0, keyStream, i * 4, 4);
        }

        keyStreamIndex = 0;
    }

    public static void print(byte[] array) {
        for (int i = 0; i < array.length; i++) {
            System.out.printf("0x%02X ", array[i]);

            if ((i + 1) % 8 == 0) {
                System.out.println();
            }
        }

        if (array.length % 8 != 0) {
            System.out.println();
        }
    }

    private static void print(int[] array) {
        for (int i = 0; i < array.length; i++) {
            System.out.printf("%08x  ", array[i]);
            if ((i + 1) % 4 == 0) {
                System.out.println();
            }
        }
        System.out.println();
    }

    public static void main(String[] args) {
        Charset charset = StandardCharsets.US_ASCII;
        byte[] key = {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B,
                0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F
        };
        byte[] nonce = {
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x4A,
                0x00, 0x00, 0x00, 0x00,
        };

        byte[] text = {
                0x4C, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
                0x6E, 0x64, 0x20, 0x47, 0x65, 0x6E, 0x74, 0x6C,
                0x65, 0x6D, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20,
                0x74, 0x68, 0x65, 0x20, 0x63, 0x6C, 0x61, 0x73,
                0x73, 0x20, 0x6F, 0x66, 0x20, 0x27, 0x39, 0x39,
                0x3A, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
                0x6F, 0x75, 0x6C, 0x64, 0x20, 0x6F, 0x66, 0x66,
                0x65, 0x72, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x6F,
                0x6E, 0x6C, 0x79, 0x20, 0x6F, 0x6E, 0x65, 0x20,
                0x74, 0x69, 0x70, 0x20, 0x66, 0x6F, 0x72, 0x20,
                0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
                0x72, 0x65, 0x2C, 0x20, 0x73, 0x75, 0x6E, 0x73,
                0x63, 0x72, 0x65, 0x65, 0x6E, 0x20, 0x77, 0x6F,
                0x75, 0x6C, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
                0x74, 0x2E
        };

        byte[] encrypted = chaCha20Encrypt(key, 1, nonce, text);
        System.out.println("Зашифрованные данные:");
        print(encrypted);
        ;


        byte[] decrypted = chaCha20Encrypt(key, 1, nonce, encrypted);
        System.out.println("Расшифрованные данные:");
        print(decrypted);
        System.out.println(new String(decrypted, StandardCharsets.US_ASCII));
    }
}
