package org.keycloak.rn.providers.login.iconcaptcha.authenticator;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.util.JsonSerialization;

import java.io.InputStream;
import java.util.*;

public class IconCaptchaUsernamePasswordForm extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(IconCaptchaUsernamePasswordForm.class);

    private static final String ICONCAPTCHA_TOKEN_FIELD = "_iconcaptcha-token";
    public static final String ICONCAPTCHA_BACK_SERVER_URL = "iconCaptchaBackServerUrl";
    public static final String ICONCAPTCHA_FRONT_SERVER_URL = "iconCaptchaFrontServerUrl";
    public static final String ICONCAPTCHA_THEME = "iconCaptchaTheme";

    private String userLanguageTag;
    private AuthenticatorConfigModel config;
    private String iconCaptchaBackServerUrl;
    private String iconCaptchaFrontServerUrl;
    private String iconCaptchaTheme;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        applyCaptcha(context);
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String token = formData.getFirst(ICONCAPTCHA_TOKEN_FIELD);
    
        boolean valid = false;
    
        if (token != null && !token.isEmpty()) {
            valid = validateIconCaptcha(token, context);
        }
    
        if (!valid) {
            LoginFormsProvider form = context.form();
            Response challenge = form
                .setAttribute("iconCaptchaRequired", true)
                .setError("IconCaptcha failed, please try again.")
                .createLoginUsernamePassword();
            applyCaptcha(context, form);
            context.forceChallenge(challenge);
            return;
        }
    
        if (!super.validateForm(context, formData)) {
            return;
        }
    
        context.success();
    }

	private void loadConfig(AuthenticationFlowContext context){
		if (context == null){
			return;
		}
        userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
        config = context.getAuthenticatorConfig();
        iconCaptchaBackServerUrl = config.getConfig().get(ICONCAPTCHA_BACK_SERVER_URL);
        iconCaptchaFrontServerUrl = config.getConfig().get(ICONCAPTCHA_FRONT_SERVER_URL);
        iconCaptchaTheme = config.getConfig().get(ICONCAPTCHA_THEME);
        if (iconCaptchaTheme == null || iconCaptchaTheme.trim().isEmpty()){
            iconCaptchaTheme = "light";
        }
	}
    
	private LoginFormsProvider applyCaptcha(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form();
        return applyCaptcha(context, form);
    }
    
    private LoginFormsProvider applyCaptcha(LoginFormsProvider form) {
        return applyCaptcha(null, form);
    }
    
    private LoginFormsProvider applyCaptcha(AuthenticationFlowContext context, LoginFormsProvider form) {
        loadConfig(context);

        form.setAttribute("iconCaptchaRequired", true);
        form.setAttribute("iconCaptchaBackServerUrl", iconCaptchaBackServerUrl);
        form.setAttribute("iconCaptchaFrontServerUrl", iconCaptchaFrontServerUrl);
        form.setAttribute("iconCaptchaTheme", iconCaptchaTheme);

        form.addScript(iconCaptchaBackServerUrl + "/assets/js/icon-captcha.min.js");
        form.addScript(iconCaptchaFrontServerUrl + "/assets/js/icon-captcha.min.js");
        return form;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        applyCaptcha(form);
        return super.createLoginForm(form);
    }

    private boolean validateIconCaptcha(String token, AuthenticationFlowContext context) {
        try {
            HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
            HttpPost post = new HttpPost(iconCaptchaBackServerUrl + "/src/captcha-request.php");

            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("_iconcaptcha-token", token));

            post.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

            HttpResponse response = httpClient.execute(post);
            InputStream content = response.getEntity().getContent();

            try (Scanner scanner = new Scanner(content).useDelimiter("\\A")) {
                String body = scanner.hasNext() ? scanner.next() : "";
                return body.contains("true");
            }
        } catch (Exception e) {
            return false;
        }
    }

}
