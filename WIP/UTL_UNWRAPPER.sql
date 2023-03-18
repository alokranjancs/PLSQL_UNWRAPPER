create or replace java source named UTL_UNWRAPPER
AS
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;

import java.security.MessageDigest;
import java.io.ByteArrayOutputStream;
import java.util.zip.Inflater;

public class UTL_UNWRAPPER {

	private static final String systemLineSeparator = System.getProperty("line.separator");

	private static final char[] map1 = new char[64];

	static {
		int i = 0;
		char c;
		for (c = 'A'; c <= 'Z'; c = (char) (c + 1))
			map1[i++] = c;
		for (c = 'a'; c <= 'z'; c = (char) (c + 1))
			map1[i++] = c;
		for (c = '0'; c <= '9'; c = (char) (c + 1))
			map1[i++] = c;
		map1[i++] = '+';
		map1[i++] = '/';
	}

	private static final byte[] map2 = new byte[128];

	static {
		int i;
		for (i = 0; i < map2.length; i++)
			map2[i] = -1;
		for (i = 0; i < 64; i++)
			map2[map1[i]] = (byte) i;
	}

	public static String encodeString(String s) {
		return new String(encode(s.getBytes()));
	}

	public static String encodeLines(byte[] in) {
		return encodeLines(in, 0, in.length, 76, systemLineSeparator);
	}

	public static String encodeLines(byte[] in, int iOff, int iLen, int lineLen, String lineSeparator) {
		int blockLen = lineLen * 3 / 4;
		if (blockLen <= 0)
			throw new IllegalArgumentException();
		int lines = (iLen + blockLen - 1) / blockLen;
		int bufLen = (iLen + 2) / 3 * 4 + lines * lineSeparator.length();
		StringBuilder buf = new StringBuilder(bufLen);
		int ip = 0;
		while (ip < iLen) {
			int l = Math.min(iLen - ip, blockLen);
			buf.append(encode(in, iOff + ip, l));
			buf.append(lineSeparator);
			ip += l;
		}
		return buf.toString();
	}

	public static char[] encode(byte[] in) {
		return encode(in, 0, in.length);
	}

	public static char[] encode(byte[] in, int iLen) {
		return encode(in, 0, iLen);
	}
	
	public static char[] encode(byte[] in, int iOff, int iLen) {
		int oDataLen = (iLen * 4 + 2) / 3;
		int oLen = (iLen + 2) / 3 * 4;
		char[] out = new char[oLen];
		int ip = iOff;
		int iEnd = iOff + iLen;
		int op = 0;
		while (ip < iEnd) {
			int i0 = in[ip++] & 0xFF;
			int i1 = (ip < iEnd) ? (in[ip++] & 0xFF) : 0;
			int i2 = (ip < iEnd) ? (in[ip++] & 0xFF) : 0;
			int o0 = i0 >>> 2;
			int o1 = (i0 & 0x3) << 4 | i1 >>> 4;
			int o2 = (i1 & 0xF) << 2 | i2 >>> 6;
			int o3 = i2 & 0x3F;
			out[op++] = map1[o0];
			out[op++] = map1[o1];
			out[op] = (op < oDataLen) ? map1[o2] : '=';
			op++;
			out[op] = (op < oDataLen) ? map1[o3] : '=';
			op++;
		}
		return out;
	}

	public static String decodeString(String s) {
		return new String(decode(s));
	}

	public static byte[] decodeLines(String s) {
		char[] buf = new char[s.length()];
		int p = 0;
		for (int ip = 0; ip < s.length(); ip++) {
			char c = s.charAt(ip);
			if (c != ' ' && c != '\r' && c != '\n' && c != '\t')
				buf[p++] = c;
		}
		return decode(buf, 0, p);
	}

	public static byte[] decode(String s) {
		return decode(s.toCharArray());
	}

	public static byte[] decode(char[] in) {
		return decode(in, 0, in.length);
	}

	public static byte[] decode(char[] in, int iOff, int iLen) {
		if (iLen % 4 != 0)
			throw new IllegalArgumentException("Length of Base64 encoded input string is not a multiple of 4.");
		while (iLen > 0 && in[iOff + iLen - 1] == '=')
			iLen--;
		int oLen = iLen * 3 / 4;
		byte[] out = new byte[oLen];
		int ip = iOff;
		int iEnd = iOff + iLen;
		int op = 0;
		while (ip < iEnd) {
			int i0 = in[ip++];
			int i1 = in[ip++];
			int i2 = (ip < iEnd) ? in[ip++] : 65;
			int i3 = (ip < iEnd) ? in[ip++] : 65;
			if (i0 > 127 || i1 > 127 || i2 > 127 || i3 > 127)
				throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
			int b0 = map2[i0];
			int b1 = map2[i1];
			int b2 = map2[i2];
			int b3 = map2[i3];
			if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0)
				throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
			int o0 = b0 << 2 | b1 >>> 4;
			int o1 = (b1 & 0xF) << 4 | b2 >>> 2;
			int o2 = (b2 & 0x3) << 6 | b3;
			out[op++] = (byte) o0;
			if (op < oLen)
				out[op++] = (byte) o1;
			if (op < oLen)
				out[op++] = (byte) o2;
		}
		return out;
	}

	// From Base64Coder End
	public static byte[] getSHA1(byte[] b) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA1");
		md.update(b);
		return md.digest();
	}

	protected static final char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0xF];
		}
		return new String(hexChars);
	}

	// HashCalculator

	public static byte[] unzip(byte[] zipped) throws DataFormatException, IOException {
		Inflater inflater = new Inflater();
		inflater.setInput(zipped);
		ByteArrayOutputStream os = new ByteArrayOutputStream(zipped.length);
		byte[] buffer = new byte[1024];
		while (!inflater.finished()) {
			int count = 0;
			count = inflater.inflate(buffer);
			os.write(buffer, 0, count);
		}
		os.close();
		return os.toByteArray();
	}

	// Unzipper
	private static int[] charmap = new int[] { 61, 101, 133, 179, 24, 219, 226, 135, 241, 82, 171, 99, 75, 181, 160, 95,
			125, 104, 123, 155, 36, 194, 40, 103, 138, 222, 164, 38, 30, 3, 235, 23, 111, 52, 62, 122, 63, 210, 169,
			106, 15, 233, 53, 86, 31, 177, 77, 16, 120, 217, 117, 246, 188, 65, 4, 129, 97, 6, 249, 173, 214, 213, 41,
			126, 134, 158, 121, 229, 5, 186, 132, 204, 110, 39, 142, 176, 93, 168, 243, 159, 208, 162, 113, 184, 88,
			221, 44, 56, 153, 76, 72, 7, 85, 228, 83, 140, 70, 182, 45, 165, 175, 50, 34, 64, 220, 80, 195, 161, 37,
			139, 156, 22, 96, 92, 207, 253, 12, 152, 28, 212, 55, 109, 60, 58, 48, 232, 108, 49, 71, 245, 51, 218, 67,
			200, 227, 94, 25, 148, 236, 230, 163, 149, 20, 224, 157, 100, 250, 89, 21, 197, 47, 202, 187, 11, 223, 242,
			151, 191, 10, 118, 180, 73, 68, 90, 29, 240, 0, 150, 33, 128, 127, 26, 130, 57, 79, 193, 167, 215, 13, 209,
			216, 255, 19, 147, 112, 238, 91, 239, 190, 9, 185, 119, 114, 231, 178, 84, 183, 42, 199, 115, 144, 102, 32,
			14, 81, 237, 248, 124, 143, 46, 244, 18, 198, 43, 131, 205, 172, 203, 59, 196, 78, 192, 105, 54, 98, 2, 174,
			136, 252, 170, 66, 8, 166, 69, 87, 211, 154, 189, 225, 35, 141, 146, 74, 17, 137, 116, 107, 145, 251, 254,
			201, 1, 234, 27, 247, 206 };

	public static String unwrap(oracle.sql.CLOB wrapped) throws DataFormatException, IOException, NoSuchAlgorithmException {
		String wrappedUnix = wrapped.replace("\r\n", "\n");
		Pattern lengthPattern = Pattern.compile("([\n][0-9a-f]+[ ])([0-9a-f]+[\n])");
		Matcher m = lengthPattern.matcher(wrappedUnix);
		if (m.find(0)) {
			String encoded;
			int encodedCodeLength = Integer.parseInt(m.group(2).trim(), 16);
			int expectedLength = m.end() + encodedCodeLength;
			if (expectedLength <= wrappedUnix.length()) {
				encoded = wrappedUnix.substring(m.end(), expectedLength);
			} else {
				throw new RuntimeException("Wrapped code seems to be truncated. Expected length of " + expectedLength
						+ " characters but got only " + wrappedUnix.length() + ".");
			}
			byte[] decoded = decodeLines(encoded);
			byte[] remapped = new byte[decoded.length];
			for (int i = 0; i < decoded.length; i++) {
				int unsignedInteger = decoded[i] & 0xFF;
				remapped[i] = (byte) charmap[unsignedInteger];
			}
			byte[] hash = Arrays.copyOfRange(remapped, 0, 20);
			byte[] zipped = Arrays.copyOfRange(remapped, 20, remapped.length);
			byte[] calculatedHash = getSHA1(zipped);
			if (Arrays.equals(hash, calculatedHash)) {
				byte[] unzipped = unzip(zipped);
				int size = unzipped.length;
				while (size > 0 && unzipped[size - 1] == 0)
					size--;
				return new String(unzipped, 0, size);
			}
			throw new RuntimeException("SHA-1 hash values do not match. Expected '" + bytesToHex(hash) + "' but got '"
					+ bytesToHex(calculatedHash) + "'. Cannot unwrap code.");
		}
		throw new RuntimeException(
				"Could not unwrap this code. Most probably it was not wrapped with the Oracle 10g, 11g or 12c wrap utility.");
	}
}
/
show err


alter java source UTL_UNWRAPPER compile
/
show err

create or replace package PKGPLSQLUNWRAPPER
is
function unwrap(src in clob) return clob;
end;
/
show err

create or replace package body PKGPLSQLUNWRAPPER
is
function unwrap(src in clob)  return clob
as language java
name 'UTL_UNWRAPPER.unwrap(oracle.sql.CLOB) return java.lang.String';
end;
/
show err
