package com.quickblox.sample.chat.core;

import com.quickblox.chat.model.QBChatMessage;

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;

import java.security.KeyPair;

public interface Chat {


    void sendMessage(QBChatMessage message) throws XMPPException, SmackException.NotConnectedException;
    byte[] getR_bytes();//juaninf
    void release() throws XMPPException;
    String encrypt(byte[] input);
    String decrypt(byte[] input);

    /*void setKeyPairM_oponnet(KeyPair keyPairM_oponnet_);//juaninf
    void setKeyPairT_oponnet(KeyPair keyPairT_oponnet_);//juaninf
    KeyPair getKeyPairM();
    KeyPair getKeyPairT();*/
}
