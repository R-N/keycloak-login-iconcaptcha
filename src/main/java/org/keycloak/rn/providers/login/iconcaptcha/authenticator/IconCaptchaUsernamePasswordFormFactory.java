package org.keycloak.rn.providers.login.iconcaptcha.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

public class IconCaptchaUsernamePasswordFormFactory  implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "iconcaptcha-u-p-form";
    public static final IconCaptchaUsernamePasswordForm SINGLETON = new IconCaptchaUsernamePasswordForm();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }
    
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "IconCaptcha Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password from login form + IconCaptcha";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property;
    
        property = new ProviderConfigProperty();
        property.setName(IconCaptchaUsernamePasswordForm.ICONCAPTCHA_BACK_SERVER_URL);
        property.setLabel("IconCaptcha Back Server URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Base URL for your IconCaptcha PHP backend that Keycloak can access");
        CONFIG_PROPERTIES.add(property);
    
        property = new ProviderConfigProperty();
        property.setName(IconCaptchaUsernamePasswordForm.ICONCAPTCHA_FRONT_SERVER_URL);
        property.setLabel("IconCaptcha Front Server URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Base URL for your IconCaptcha PHP backend that user can access");
        CONFIG_PROPERTIES.add(property);
    
        property = new ProviderConfigProperty();
        property.setName(IconCaptchaUsernamePasswordForm.ICONCAPTCHA_THEME);
        property.setLabel("IconCaptcha Theme");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Theme for IconCaptcha (e.g., light, dark). Leave empty for default.");
        property.setDefaultValue("light");  // Visible in Admin UI as pre-filled value
        CONFIG_PROPERTIES.add(property);
    }
    
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}