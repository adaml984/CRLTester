package com.example.testcrl;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.util.concurrent.ExecutionException;

public class MainActivity extends AppCompatActivity {

    private Button _testButton;
    private TextView urlEditText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        urlEditText = (TextView) findViewById(R.id.urlText);
        _testButton = (Button) findViewById(R.id.testUrlButton);
        _testButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                try {
                    String url = urlEditText.getText().toString();
                    UrlTestResult result = checkUrl(url);
                    AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());

                    if (result.IsSuccess) {
                        builder.setMessage("Can display " + url)
                                .setTitle("CRL Tester");
                    } else {
                        if (result.LastException == null)
                            builder.setMessage("Can't display " + url)
                                    .setTitle("CRL Tester");
                        else {
                            String message = result.LastException.getMessage();
                            if (message != null && !message.isEmpty())
                                builder.setMessage(message)
                                        .setTitle("CRL Tester");
                            else
                                builder.setMessage("Can't display " + url)
                                        .setTitle("CRL Tester");
                        }
                    }
                    AlertDialog dialog = builder.create();
                    dialog.show();

                } catch (ExecutionException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private Activity getActivity() {
        return this;
    }

    private UrlTestResult checkUrl(String url) throws ExecutionException, InterruptedException {
        OpenUrlInBackground d = new OpenUrlInBackground();
        return d.execute(url).get();
    }
}
