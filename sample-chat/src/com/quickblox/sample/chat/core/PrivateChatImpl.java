package com.quickblox.sample.chat.core;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.lang.Byte;
import java.util.Iterator;
import java.util.Map;

import android.util.Base64;
import android.telephony.TelephonyManager;
import android.util.Base64;
import android.util.Log;

import com.quickblox.chat.QBChatService;
import com.quickblox.chat.QBPrivateChat;
import com.quickblox.chat.QBPrivateChatManager;
import com.quickblox.chat.exception.QBChatException;
import com.quickblox.chat.listeners.QBMessageListenerImpl;
import com.quickblox.chat.listeners.QBPrivateChatManagerListener;
import com.quickblox.chat.model.QBChatMessage;
import com.quickblox.sample.chat.ui.activities.ChatActivity;
import com.quickblox.users.model.QBUser;

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;

import de.flexiprovider.api.Registry;
import de.flexiprovider.pqc.hbc.cmss.CMSSPrivateKey;
import de.flexiprovider.pqc.hbc.cmss.CMSSPublicKey;

public class PrivateChatImpl extends QBMessageListenerImpl<QBPrivateChat>
		implements Chat, QBPrivateChatManagerListener {

	private static final String TAG = "PrivateChatManagerImpl";
	private static final String JUAN = "JUAN";
	private ChatActivity chatActivity;
	private KeyPair keyPairM;
	private KeyPair keyPairT;
	private KeyPair keyPairM_oponnet;
	private KeyPair keyPairT_oponnet;
	private KeyPair R;
	private QBPrivateChatManager privateChatManager;
	private QBPrivateChat privateChat;
	private Integer opponentID1;
	private byte[] K;
	private byte[] R_bytes;
	public PrivateChatImpl(ChatActivity chatActivity, Integer opponentID) {
		this.chatActivity = chatActivity;
		opponentID1 = opponentID;
		initManagerIfNeed();

		// initIfNeed private chat
		//
		privateChat = privateChatManager.getChat(opponentID);
		if (privateChat == null) {
			privateChat = privateChatManager.createChat(opponentID, this);
		} else {
			privateChat.addMessageListener(this);
		}

		//Generating key
		try {
			Security.addProvider(new de.flexiprovider.pqc.FlexiPQCProvider());
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(
					"CMSSwithSHA1andWinternitzOTS_1", "FlexiPQC");
			kpg.initialize(10);
			keyPairM = kpg.generateKeyPair();

			Log.w(JUAN, "constructor keyPairM: " + keyPairM.getPublic());
			SecureRandom random = new SecureRandom();
			KeyPairGenerator keyPairGeneratorT = KeyPairGenerator.getInstance("McEliece", "FlexiPQC");
			//KeyFactory keyfactory = KeyFactory.getInstance("McEliece", "FlexiPQC");
			//keyPairGeneratorT.initialize(1024);
			keyPairT = keyPairGeneratorT.genKeyPair();

			/*KeyPairGenerator keyPairGeneratorM = KeyPairGenerator.getInstance("RSA");
			keyPairGeneratorM.initialize(1024);
			keyPairM = keyPairGeneratorM.genKeyPair();
			KeyPairGenerator keyPairGeneratorT = KeyPairGenerator.getInstance("RSA");
			keyPairGeneratorT.initialize(1024);
			keyPairT = keyPairGeneratorT.genKeyPair();*/
			//Log.w(JUAN,"modulusT: " + ((RSAPublicKey)keyPairT.getPublic()).getModulus());
			//Log.w(JUAN,"modulusM: " + ((RSAPublicKey)keyPairM.getPublic()).getModulus());
			//Log.w(JUAN, "expM: " + ((RSAPublicKey) keyPairM.getPublic()).getPublicExponent());
			//Log.w(JUAN, "expT: " + ((RSAPublicKey) keyPairT.getPublic()).getPublicExponent());
			//Log.w(JUAN, "on Create keyPairM.getPublic(): " + Base64.encodeToString(((RSAPublicKey) keyPairM.getPublic()).getEncoded(), Base64.DEFAULT));
			R_bytes = new byte[32];
			random.nextBytes(R_bytes);
		} catch (Exception e) {
			Log.e(JUAN, "failed creating keyM", e);
		}


	}

	private void initManagerIfNeed() {
		if (privateChatManager == null) {
			privateChatManager = QBChatService.getInstance()
					.getPrivateChatManager();

			privateChatManager.addPrivateChatManagerListener(this);
		}
	}

	@Override
	public void sendMessage(QBChatMessage message) throws XMPPException,
			SmackException.NotConnectedException {
		privateChat.sendMessage(message);
	}

	@Override
	public void release() {
		Log.w(TAG, "release private chat");
		privateChat.removeMessageListener(this);
		privateChatManager.removePrivateChatManagerListener(this);
	}

	public static RSAPublicKey createPublicKey(BigInteger keyInt, BigInteger exponentInt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		try{
			RSAPublicKeySpec keySpeck = new RSAPublicKeySpec(keyInt, exponentInt);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return  (RSAPublicKey) keyFactory.generatePublic(keySpeck);
		} catch(Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	private QBChatMessage step1(QBChatMessage message){
		QBChatMessage chatMessage = new QBChatMessage();
		try {
			//Security.addProvider(new de.flexiprovider.pqc.FlexiPQCProvider());
			byte[] R_bytes_rec = Base64.decode(message.getBody().getBytes(), Base64.DEFAULT);
			Integer user_id = opponentID1;

			String R_str = Base64.encodeToString(R_bytes_rec, Base64.DEFAULT);
			Log.w(JUAN, "own R: " + Base64.encodeToString(R_bytes, Base64.DEFAULT));
			Log.w(JUAN, "Receveid string: " + R_str + "first character" + message.getProperties().get("step"));
			Log.w(JUAN, "keyPairM.getPublic(): " + keyPairM.getPublic());
			//Log.w(JUAN, "keyPairM.getPublic(): " + Base64.encodeToString(keyPairM.getPublic().getEncoded(), Base64.DEFAULT));
			PrivateKey encPrivateKey = keyPairM.getPrivate();//juaninf
			KeySpec privateKeySpec = new PKCS8EncodedKeySpec(encPrivateKey.getEncoded());//juaninf
			KeyFactory keyFactory = KeyFactory.getInstance("CMSS", "FlexiPQC");//juaninf
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);//juaninf
			Signature signature = Signature.getInstance("CMSSwithSHA1andWinternitzOTS_1","FlexiPQC");

			//Signature signature = Signature.getInstance("SHA1withRSA", "BC");
			//signature.initSign((RSAPrivateKey)keyPairM.getPrivate(), new SecureRandom());
			signature.initSign(privateKey);//juaninf
			//byte[] pKTbytes = Base64.encode(keyPairT.getPublic().getEncoded(), Base64.DEFAULT);
			//byte[] pKTbytes = (((RSAPublicKey)keyPairT.getPublic()).getModulus()).toByteArray();
			byte[] pKTbytes = (keyPairT.getPublic()).getEncoded();
			//Log.w(JUAN,"modulus: " + ((RSAPublicKey)keyPairT.getPublic()).getModulus());
			Log.w(JUAN, "size PKTbytes: " + pKTbytes.length);
			byte[] R_pkT = new byte[R_bytes_rec.length+pKTbytes.length];
			System.arraycopy(R_bytes_rec, 0, R_pkT, 0, R_bytes_rec.length);
			System.arraycopy(pKTbytes, 0, R_pkT, R_bytes_rec.length, pKTbytes.length);

			Log.w(JUAN, "R||pkT: " + Base64.encodeToString(R_pkT, Base64.DEFAULT));

			signature.update(R_pkT);
			byte[] sigBytes = signature.sign();
			String sig_str = Base64.encodeToString(sigBytes, Base64.DEFAULT);
			Log.w(JUAN, "signature string: " + sig_str);
			//byte[] pKMbytes = Base64.encode(((RSAPublicKey)keyPairM.getPublic()).getEncoded(), Base64.DEFAULT);
			//byte[] pKMbytes = (((RSAPublicKey)keyPairM.getPublic()).getModulus()).toByteArray();
			//byte[] pKMbytes = (((RSAPublicKey)keyPairT.getPublic()).getModulus()).toByteArray();
			byte[] pKMbytes = ((CMSSPublicKey)keyPairM.getPublic()).getEncoded();
			Log.w(JUAN, "sigBytes.length"+sigBytes.length);
			Log.w(JUAN, "pKMbytes.length" + pKMbytes.length);
			byte[] pkT_sig_pkM_bytes = new byte[pKTbytes.length+sigBytes.length+pKMbytes.length];

			System.arraycopy(pKTbytes, 0, pkT_sig_pkM_bytes, 0, pKTbytes.length);
			System.arraycopy(sigBytes, 0, pkT_sig_pkM_bytes, pKTbytes.length, sigBytes.length);
			System.arraycopy(pKMbytes, 0, pkT_sig_pkM_bytes, pKTbytes.length + sigBytes.length, pKMbytes.length);
			String pkT_sig_str = Base64.encodeToString(pkT_sig_pkM_bytes, Base64.DEFAULT);
			//Log.w(JUAN, "TPub_string: " + Base64.encodeToString(pKTbytes, Base64.DEFAULT));
			//Log.w(JUAN, "sig_string: " + Base64.encodeToString(sigBytes, Base64.DEFAULT));
			//Log.w(JUAN, "pKM_string: " + Base64.encodeToString(pKMbytes, Base64.DEFAULT));
			//Log.w(JUAN, "pkT||signature string: "+pkT_sig_str);
			chatMessage.setBody(pkT_sig_str);
			chatMessage.setProperty("step","2");
			chatMessage.setProperty("save_to_history", "0");
			chatMessage.setDateSent(new Date().getTime() / 1000);

		} catch (Exception e) {
			Log.e(JUAN, "failed to exchange key step 1 ", e);
		}
		return chatMessage;
	}

	private QBChatMessage step2(QBChatMessage message){
		//Security.addProvider(new de.flexiprovider.pqc.FlexiPQCProvider());
		Log.w(JUAN, "own R: " + Base64.encodeToString(R_bytes, Base64.DEFAULT));
		QBChatMessage chatMessage = new QBChatMessage();
		byte[] pkT_R_bytes = Base64.decode(message.getBody().getBytes(), Base64.DEFAULT);
		byte[] pKTbytes = Arrays.copyOfRange(pkT_R_bytes, 0, 383542);
		//byte[] sig_bytes = Arrays.copyOfRange(pkT_R_bytes, 129, pkT_R_bytes.length-129);
		byte[] sig_bytes = Arrays.copyOfRange(pkT_R_bytes, 383542, 383542+7168);
		//byte[] pKMbytes = Arrays.copyOfRange(pkT_R_bytes, pkT_R_bytes.length-129, pkT_R_bytes.length);
		byte[] pKMbytes = Arrays.copyOfRange(pkT_R_bytes, 383542+7168, pkT_R_bytes.length);

		//Log.w(JUAN, "TPub_string: " + Base64.encodeToString(pKTbytes, Base64.DEFAULT));
		//Log.w(JUAN, "sig_string: " + Base64.encodeToString(sig_bytes, Base64.DEFAULT));
		//Log.w(JUAN, "pKM_string: " + Base64.encodeToString(pKMbytes, Base64.DEFAULT));
		try {
			//PublicKey encPublicKey =  keyPairM.getPublic();
			KeySpec publicKeySpec = new X509EncodedKeySpec(pKMbytes);
			KeyFactory keyFactory = KeyFactory.getInstance("CMSS", "FlexiPQC");//juaninf
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			Signature signature = Signature.getInstance("CMSSwithSHA1andWinternitzOTS_1", "FlexiPQC");


			//Signature signature = Signature.getInstance("SHA1withRSA", "BC");
			//BigInteger modu = ((RSAPublicKey) keyPairT.getPublic()).getModulus();//juaninf
			//BigInteger expo = ((RSAPublicKey) keyPairT.getPublic()).getPublicExponent();

			//RSAPublicKey pkM	= createPublicKey(new BigInteger(pKMbytes), expo);
			//RSAPublicKey pkT	= createPublicKey(new BigInteger(pKTbytes), expo);
			//KeySpec publicKeySpec = new X509EncodedKeySpec(pKMbytes);
			KeyFactory keyFactoryMc = KeyFactory.getInstance("McEliece", "FlexiPQC");//juaninf
			PublicKey mceliece_pk = (PublicKey)keyFactoryMc.generatePublic(new X509EncodedKeySpec(pKTbytes));
			//signature.initVerify((RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(new PKCS8EncodedKeySpec(pKMbytes)));
			//Log.w(JUAN, "pkM: " + Base64.encodeToString(pkM.getEncoded(), Base64.DEFAULT));
			//signature.initVerify(pkM);
			signature.initVerify(publicKey);
			Log.w(JUAN, "keyPairM.getPublic(): " + Base64.encodeToString(keyPairM.getPublic().getEncoded(), Base64.DEFAULT));
			byte[] R_pkT = new byte[R_bytes.length+pKTbytes.length];
			System.arraycopy(R_bytes, 0, R_pkT, 0, R_bytes.length);
			System.arraycopy(pKTbytes, 0, R_pkT, R_bytes.length, pKTbytes.length);
			Log.w(JUAN, "R||pkT: " + Base64.encodeToString(R_pkT, Base64.DEFAULT));
			signature.update(R_pkT);
			boolean ver = signature.verify(sig_bytes);
			Log.w(JUAN, "verify: " + ver);

			byte[] K_byte = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

			KeyGenerator KeyGen=KeyGenerator.getInstance("AES");
			KeyGen.init(128);

			SecretKey key=KeyGen.generateKey();

			//SecretKeySpec key = new SecretKeySpec(K_byte, "AES");
			K = key.getEncoded();
			// get an RSA cipher object and print the provider
			Log.w(JUAN, "K_str: "+Base64.encodeToString(K, Base64.DEFAULT));
			final Cipher cipher = Cipher.getInstance("McEliece");
			// encrypt the plain text using the public key
			//Log.w(JUAN,"modulus: " + (pkT).getModulus());
			cipher.init(Cipher.ENCRYPT_MODE, mceliece_pk);
			byte[] X = cipher.doFinal(K);
			String X_str = Base64.encodeToString(X, Base64.DEFAULT);
			Log.w(JUAN, "X_str: "+X_str);
			chatMessage.setBody(X_str);
			chatMessage.setProperty("step", "3");
			chatMessage.setProperty("save_to_history", "0");
			chatMessage.setDateSent(new Date().getTime() / 1000);
		} catch (Exception e) {
			Log.e(JUAN, "failed to exchange key step 2 ", e);
		}
		return chatMessage;
	}

	private QBChatMessage step3(QBChatMessage message){
		//Log.w(JUAN,"modulus: " + ((RSAPublicKey)keyPairT.getPublic()).getModulus());
		QBChatMessage chatMessage = new QBChatMessage();
		try {
			String X_str = message.getBody();
			byte[] X_bytes = Base64.decode(message.getBody().getBytes(), Base64.DEFAULT);
			Log.w(JUAN, "X_str: "+X_str);
			final Cipher  mce = Cipher.getInstance("McEliece");
			mce.init(Cipher.DECRYPT_MODE, keyPairT.getPrivate());
			K = mce.doFinal(X_bytes);
			Log.w(JUAN, "K_str: "+Base64.encodeToString(K, Base64.DEFAULT));
		} catch (Exception e) {
			Log.e(JUAN, "failed to exchange key step 2 ", e);
		}
		return null;
	}
	public byte[] getR_bytes(){
		return R_bytes;
	}
	/*public void setKeyPairM_oponnet(KeyPair keyPairM_oponnet_){
		keyPairM_oponnet = keyPairM_oponnet_;
	}
	public void setKeyPairT_oponnet(KeyPair keyPairT_oponnet_){
		keyPairT_oponnet = keyPairT_oponnet_;
	}

	public KeyPair getKeyPairM(){
		return keyPairM;
	}
	public KeyPair getKeyPairT(){
		return keyPairT;
	}*/
	public String encrypt(byte[] input){
        //byte[] K = null;
		try {
			IvParameterSpec iv = new IvParameterSpec(Base64.decode("Hola".getBytes(), Base64.DEFAULT));
			SecretKeySpec key = new SecretKeySpec(K, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
			int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
			ctLength += cipher.doFinal(cipherText, ctLength);
			return Base64.encodeToString(cipherText, Base64.DEFAULT);
		} catch (Exception e) {
			Log.e(JUAN, "failed to encrypt ", e);
		}
		return null;
	}

	public String decrypt(byte[] input){
		try {
			IvParameterSpec iv = new IvParameterSpec(Base64.decode("Hola".getBytes(), Base64.DEFAULT));
			SecretKeySpec key = new SecretKeySpec(K, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] plainText = new byte[cipher.getOutputSize(input.length)];
			int ctLength = cipher.update(input, 0, input.length, plainText, 0);
			ctLength += cipher.doFinal(plainText, ctLength);
			return Base64.encodeToString(plainText, Base64.NO_PADDING);
		} catch (Exception e) {
			Log.e(JUAN, "failed to decrypt ", e);
		}
		return null;
	}
	@Override
	public void processMessage(QBPrivateChat chat, QBChatMessage message) {

		Log.w(JUAN, "opponent: " + ChatService.getInstance().getDialogsUsers().get(opponentID1).getLogin());
		try {

			String step = message.getProperties().get("step");
			switch (step) {
				case "1":
					Log.w(JUAN, ":::::::::::::::::::::::Step 1::::::::::::::::::::::::::\n");
					QBChatMessage chatMessage = step1(message);
					try {
						Log.w(JUAN, "Sending signature ...");
						chat.sendMessage(chatMessage);
					} catch (XMPPException e) {
						Log.e(TAG, "failed to send a message", e);
					} catch (SmackException sme) {
						Log.e(TAG, "failed to send a message", sme);
					}
					break;
				case "2":
					Log.w(JUAN, ":::::::::::::::::::::::Step 2::::::::::::::::::::::::::\n");
					Log.w(JUAN,"Follow step 2");
					QBChatMessage chatMessage1 = step2(message);
					try {
						Log.w(JUAN, "Sending secret key ...");
						chat.sendMessage(chatMessage1);
					} catch (XMPPException e) {
						Log.e(TAG, "failed to send a message", e);
					} catch (SmackException sme) {
						Log.e(TAG, "failed to send a message", sme);
					}
					break;
				case "3":
					Log.w(JUAN, ":::::::::::::::::::::::Step 3::::::::::::::::::::::::::\n");
					QBChatMessage chatMessage2  = step3(message);
					break;
				case "-1":
					Log.w(JUAN, ":::::::::::::::::::::::Text::::::::::::::::::::::::::\n");
					Log.w(JUAN,"recevied message: " + message.getBody());
					String plainEncodedText = this.decrypt(Base64.decode(message.getBody(), Base64.DEFAULT));
					byte[] plainTextAsByte = Base64.decode(plainEncodedText, Base64.DEFAULT);
					String plainTextAgain = new String(plainTextAsByte , "UTF-8");
					message.setBody(plainTextAgain);
					chatActivity.showMessage(message);
					break;
			}

		} catch (Exception e) {
			Log.e(JUAN, "failed to exchange key ", e);
		}


		//chatActivity.showMessage(message);
	}

	@Override
	public void processError(QBPrivateChat chat, QBChatException error,
							 QBChatMessage originChatMessage) {

	}

	@Override
	public void chatCreated(QBPrivateChat incomingPrivateChat,
							boolean createdLocally) {
		if (!createdLocally) {
			Log.w(JUAN,
					"LOCALLY private chat created: " + incomingPrivateChat.getParticipant()
							+ ", createdLocally:" + createdLocally);
			privateChat = incomingPrivateChat;
			privateChat.addMessageListener(PrivateChatImpl.this);
		}


	}

}
