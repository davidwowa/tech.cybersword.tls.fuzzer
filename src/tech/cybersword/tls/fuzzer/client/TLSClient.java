package tech.cybersword.tls.fuzzer.client;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import tech.cybersword.tls.fuzzer.common.CommonProperties;
import tech.cybersword.tls.fuzzer.util.LoggerUtil;
import tech.cybersword.tls.fuzzer.util.StringUtil;

public class TLSClient {

	private static final Logger logger = LoggerUtil.getLogger(TLSClient.class.getName());

	private static TLSClient instance;

	private TLSClient() {
		if (logger.isLoggable(Level.INFO)) {
			logger.info(String.format("create instance of %s", this.getClass().getName()));
		}
	}

	public static TLSClient getInstance() {
		if (null == instance) {
			instance = new TLSClient();
		}
		return instance;
	}

	public byte[] sendTLSMessage(String host, int port, byte[] message) {
		boolean send = false;
		boolean receive = false;
		try (Socket socket = new Socket(host, port);
				OutputStream out = socket.getOutputStream();
				InputStream in = socket.getInputStream()) {

			socket.setSoTimeout(CommonProperties.getInstance().getRequestTimeout());

			out.write(message, 0, message.length);
			send = true;
			byte[] buffer = new byte[1024];
			int bytesRead;
			ByteArrayOutputStream response = new ByteArrayOutputStream();

			while (true) {
				try {
					bytesRead = in.read(buffer);
					if (bytesRead == -1) {
						break;
					}
					response.write(buffer, 0, bytesRead);
				} catch (SocketTimeoutException e) {
					break;
				}
			}

			byte[] arr = response.toByteArray();
			receive = arr.length > 0;
			if (logger.isLoggable(Level.FINE)) {
				logger.log(Level.FINE, String.format("Response from server: %s",
						StringUtil.getInstance().toHexString(arr)));
			}

			if (arr.length > 0 && logger.isLoggable(Level.INFO)) {
				logger.info(String.format("\n%s:%s \nrequest:%s \nresponse %s", host, port,
						StringUtil.getInstance().toHexString(message), StringUtil.getInstance().toHexString(arr)));
			}

			return arr;
		} catch (Exception e) {
				if (logger.isLoggable(Level.SEVERE)) {
					logger.log(Level.SEVERE,
							String.format("Error on \nsend(%b)/receive(%b) \n" + //
									"from %s:%s message %s", send, receive, host, port,
									StringUtil.getInstance().toHexString(message)), e);
				}
			}
		return new byte[0];
		// Socket socket = new Socket(host, port);
		// OutputStream out = socket.getOutputStream();
		// out.write(message, 0, message.length);
		// out.close();
		// socket.close();
		// return getResponse(host, port);
	}
}
