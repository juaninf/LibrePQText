package com.quickblox.sample.chat.ui.activities;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;

import com.quickblox.chat.model.QBDialogType;
import com.quickblox.core.QBEntityCallbackImpl;
import com.quickblox.chat.QBChatService;
import com.quickblox.chat.model.QBChatMessage;
import com.quickblox.chat.model.QBDialog;
import com.quickblox.core.request.QBRequestGetBuilder;
import com.quickblox.sample.chat.R;
import com.quickblox.sample.chat.core.Chat;
import com.quickblox.sample.chat.core.ChatService;
import com.quickblox.sample.chat.core.GroupChatImpl;
import com.quickblox.sample.chat.core.PrivateChatImpl;
import com.quickblox.sample.chat.ui.adapters.ChatAdapter;

import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.MessageListener;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;

import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.security.SecureRandom;
import android.util.Base64;

import java.security.Signature;
import de.flexiprovider.api.Registry;
import de.flexiprovider.core.FlexiCoreProvider;
import de.flexiprovider.pqc.FlexiPQCProvider;
import de.flexiprovider.pqc.hbc.cmss.CMSSKeyPairGenerator;
import de.flexiprovider.pqc.hbc.cmss.CMSSPrivateKey;

public class ChatActivity extends BaseActivity {
    private static final String JUAN = "JUAN";
    private static final String TAG = ChatActivity.class.getSimpleName();

    public static final String EXTRA_DIALOG = "dialog";
    private final String PROPERTY_SAVE_TO_HISTORY = "save_to_history";

    private EditText messageEditText;
    private ListView messagesContainer;
    private Button sendButton;
    private ProgressBar progressBar;
    private ChatAdapter adapter;
    private Chat chat;
    private QBDialog dialog;

    public static void start(Context context, Bundle bundle) {
        Intent intent = new Intent(context, ChatActivity.class);
        intent.putExtras(bundle);
        context.startActivity(intent);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);

        initViews();

        // Init chat if the session is active
        //
        if(isSessionActive()){
            initChat();
        }

        ChatService.getInstance().addConnectionListener(chatConnectionListener);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        ChatService.getInstance().removeConnectionListener(chatConnectionListener);
    }

    @Override
    public void onBackPressed() {
        try {
            chat.release();
        } catch (XMPPException e) {
            Log.e(TAG, "failed to release chat", e);
        }
        super.onBackPressed();

        Intent i = new Intent(ChatActivity.this, DialogsActivity.class);
        startActivity(i);
        finish();
    }

    private void initViews() {
        messagesContainer = (ListView) findViewById(R.id.messagesContainer);
        messageEditText = (EditText) findViewById(R.id.messageEdit);
        progressBar = (ProgressBar) findViewById(R.id.progressBar);
        TextView companionLabel = (TextView) findViewById(R.id.companionLabel);

        // Setup opponents info
        //
        Intent intent = getIntent();
        dialog = (QBDialog)intent.getSerializableExtra(EXTRA_DIALOG);
        if(dialog.getType() == QBDialogType.GROUP){
            RelativeLayout container = (RelativeLayout) findViewById(R.id.container);
            TextView meLabel = (TextView) findViewById(R.id.meLabel);
            container.removeView(meLabel);
            container.removeView(companionLabel);
        }else if(dialog.getType() == QBDialogType.PRIVATE){
            Integer opponentID = ChatService.getInstance().getOpponentIDForPrivateDialog(dialog);
            companionLabel.setText(ChatService.getInstance().getDialogsUsers().get(opponentID).getLogin());
        }

        // Send button
        //
        sendButton = (Button) findViewById(R.id.chatSendButton);
        sendButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String messageText = messageEditText.getText().toString();
                if (TextUtils.isEmpty(messageText)) {
                    return;
                }

                // Send chat message
                //
                QBChatMessage chatMessage = new QBChatMessage();
                SecureRandom random = new SecureRandom();
                byte bytes[] = new byte[32];
                random.nextBytes(bytes);
                bytes.toString();
                //String messageTextEnc = chat.encrypt(Base64.decode(messageText.getBytes(), Base64.DEFAULT));

                try {

                    Security.addProvider(new FlexiCoreProvider());
                    Security.addProvider(new FlexiPQCProvider());
                    de.flexiprovider.api.keys.KeyPairGenerator kpg = (CMSSKeyPairGenerator) Registry.getKeyPairGenerator("CMSSwithSHA1andWinternitzOTS_1");
                    de.flexiprovider.api.keys.KeyPair keyPair = kpg.genKeyPair();
                    int i;
                    byte[] data = "test".getBytes("UTF8");
                    Signature sig = Signature
                            .getInstance("CMSSwithSHA1andWinternitzOTS_1");
                    sig.initSign((CMSSPrivateKey) keyPair.getPrivate());
                    long startTime = System.nanoTime();
                    sig.update(data);
                    //sig.update(data);
                    //System.out.println("Total Time: " + (System.nanoTime() - startTime));
                    byte[] signatureBytes = sig.sign();
                    Log.e(JUAN, "Signature lenght CMSS:" + signatureBytes.length);

                    String messageTextEnc = chat.encrypt(messageText.getBytes("UTF-8"));
                    String text = "hola, hi, anything u want";
                    byte[] plainText = text.getBytes("UTF-8");
                    String base64 = chat.encrypt(plainText);
                    byte[] cipherText = Base64.decode(base64, Base64.DEFAULT);
                    String plainEncodedText = chat.decrypt(cipherText);
                    byte[] plainTextAsByte = Base64.decode(plainEncodedText, Base64.DEFAULT);
                    String plainTextAgain = new String(plainTextAsByte , "UTF-8");
                    Log.w(JUAN, text + "=" + plainTextAgain);

                chatMessage.setProperty("step", "-1");
                chatMessage.setBody(messageTextEnc);
                chatMessage.setProperty(PROPERTY_SAVE_TO_HISTORY, "1");
                chatMessage.setDateSent(new Date().getTime() / 1000);
                }catch (Exception e){

                }
                try {
                    chat.sendMessage(chatMessage);
                } catch (XMPPException e) {
                    Log.e(TAG, "failed to send a message", e);
                } catch (SmackException sme) {
                    Log.e(TAG, "failed to send a message", sme);
                }

                messageEditText.setText("");

                if (dialog.getType() == QBDialogType.PRIVATE) {
                    chatMessage.setBody(messageText);//juaninf
                    showMessage(chatMessage);
                }
            }
        });
    }

    private void initChat(){

        if(dialog.getType() == QBDialogType.GROUP){
            chat = new GroupChatImpl(this);

            // Join group chat
            //
            progressBar.setVisibility(View.VISIBLE);
            //
            joinGroupChat();

        }else if(dialog.getType() == QBDialogType.PRIVATE){
            Integer opponentID = ChatService.getInstance().getOpponentIDForPrivateDialog(dialog);

            chat = new PrivateChatImpl(this, opponentID);

            //Log.w(JUAN,"KeyAgreement"+ChatService.getInstance().getCurrentUser().getId());
            loadChatHistory();
            keyAgreement(chat, opponentID);
        }
    }

    private void keyAgreement(Chat chat, Integer opponentID){
        Log.w(JUAN, "Abre: " + ChatService.getInstance().getCurrentUser().getLogin());
        try{


            //STEP 1
            QBChatMessage chatMessage = new QBChatMessage();
            /*SecureRandom random = new SecureRandom();
            byte[] R = new byte[32];

            random.nextBytes(R);*/
            byte[] R = chat.getR_bytes();
            //chat.setKeyPairM_oponnet(chat.get);
            Log.w(JUAN, "send random bytes: " + String.format("0x%02X", R[0]));
            String R_str = Base64.encodeToString(R, Base64.DEFAULT);
            chatMessage.setBody(R_str);
            chatMessage.setProperty("step","1");
            Log.w(JUAN, "send string: " + R_str);
            chatMessage.setProperty(PROPERTY_SAVE_TO_HISTORY, "1");
            chatMessage.setDateSent(new Date().getTime() / 1000);

            try {
                chat.sendMessage(chatMessage);
            } catch (XMPPException e) {
                Log.e(TAG, "failed to send a message", e);
            } catch (SmackException sme) {
                Log.e(TAG, "failed to send a message", sme);
            }


        }catch(Exception e){
            Log.e(JUAN, "failed to exchange key", e);
        }
    }


    private void joinGroupChat(){
        ((GroupChatImpl) chat).joinGroupChat(dialog, new QBEntityCallbackImpl() {
            @Override
            public void onSuccess() {

                // Load Chat history
                //
                loadChatHistory();
            }

            @Override
            public void onError(List list) {
                AlertDialog.Builder dialog = new AlertDialog.Builder(ChatActivity.this);
                dialog.setMessage("error when join group chat: " + list.toString()).create().show();
            }
        });
    }



    private void loadChatHistory(){
        QBRequestGetBuilder customObjectRequestBuilder = new QBRequestGetBuilder();
        customObjectRequestBuilder.setPagesLimit(100);
        customObjectRequestBuilder.sortDesc("date_sent");

        QBChatService.getDialogMessages(dialog, customObjectRequestBuilder, new QBEntityCallbackImpl<ArrayList<QBChatMessage>>() {
            @Override
            public void onSuccess(ArrayList<QBChatMessage> messages, Bundle args) {

                adapter = new ChatAdapter(ChatActivity.this, new ArrayList<QBChatMessage>());
                messagesContainer.setAdapter(adapter);

                for(int i=messages.size()-1; i>=0; --i) {
                    QBChatMessage msg = messages.get(i);
                    showMessage(msg);
                }
                progressBar.setVisibility(View.GONE);
            }

            @Override
            public void onError(List<String> errors) {
                if (!ChatActivity.this.isFinishing()) {
                    AlertDialog.Builder dialog = new AlertDialog.Builder(ChatActivity.this);
                    dialog.setMessage("load chat history errors: " + errors).create().show();
                }
            }
        });
    }

    public void showMessage(QBChatMessage message) {
        adapter.add(message);
        //Log.w(JUAN, "showMessage:"+message);
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                adapter.notifyDataSetChanged();
                scrollDown();
            }
        });
    }

    private void scrollDown() {
        messagesContainer.setSelection(messagesContainer.getCount() - 1);
    }


    ConnectionListener chatConnectionListener = new ConnectionListener() {
        @Override
        public void connected(XMPPConnection connection) {
            Log.i(TAG, "connected");
        }

        @Override
        public void authenticated(XMPPConnection connection) {
            Log.i(TAG, "authenticated");
        }

        @Override
        public void connectionClosed() {
            Log.i(TAG, "connectionClosed");
        }

        @Override
        public void connectionClosedOnError(final Exception e) {
            Log.i(TAG, "connectionClosedOnError: " + e.getLocalizedMessage());

            // leave active room
            //
            if(dialog.getType() == QBDialogType.GROUP){
                ChatActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        ((GroupChatImpl) chat).leave();
                    }
                });
            }
        }

        @Override
        public void reconnectingIn(final int seconds) {
            if(seconds % 5 == 0) {
                Log.i(TAG, "reconnectingIn: " + seconds);
            }
        }

        @Override
        public void reconnectionSuccessful() {
            Log.i(TAG, "reconnectionSuccessful");

            // Join active room
            //
            if(dialog.getType() == QBDialogType.GROUP){
                ChatActivity.this.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        joinGroupChat();
                    }
                });
            }
        }

        @Override
        public void reconnectionFailed(final Exception error) {
            Log.i(TAG, "reconnectionFailed: " + error.getLocalizedMessage());
        }
    };


    //
    // ApplicationSessionStateCallback
    //

    @Override
    public void onStartSessionRecreation() {

    }

    @Override
    public void onFinishSessionRecreation(final boolean success) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (success) {
                    initChat();
                }
            }
        });
    }
}
