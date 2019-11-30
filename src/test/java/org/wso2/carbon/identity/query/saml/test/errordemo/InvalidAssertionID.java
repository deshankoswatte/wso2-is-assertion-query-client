/*
 *
 *  * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *  *
 *  * WSO2 Inc. licenses this file to you under the Apache License,
 *  * Version 2.0 (the "License"); you may not use this file except
 *  * in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing,
 *  * software distributed under the License is distributed on an
 *  * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  * KIND, either express or implied.  See the License for the
 *  * specific language governing permissions and limitations
 *  * under the License.
 *
 */

package org.wso2.carbon.identity.query.saml.test.errordemo;


import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AssertionIDRef;
import org.opensaml.saml.saml2.core.AssertionIDRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.impl.AssertionIDRefBuilder;
import org.opensaml.saml.saml2.core.impl.AssertionIDRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.test.SPSignKeyDataHolder;
import org.wso2.carbon.identity.query.saml.util.OpenSAML3Util;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;

import java.io.File;
import java.util.UUID;

public class InvalidAssertionID {

    private final static Log log = LogFactory.getLog(InvalidAssertionID.class);

    private static final String END_POINT = "https://localhost:9443/services/SAMLQueryService";
    private static final String SOAP_ACTION = "http://wso2.org/identity/saml/query";
    private static final String DIGEST_METHOD_ALGO = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private static final String SIGNING_ALGO = "http://www.w3.org/2000/09/xmldsig#sha1";
    private static final String TRUST_STORE = "wso2carbon.jks";
    private static final String TRUST_STORE_PASSWORD = "wso2carbon";
    private static final String ISSUER_ID = "travelocity.com";
    private static final String NAME_ID = "admin";
    private static final String ASSERTION_ID = "455435747476658";

    public static void main(String[] ags) throws Exception {

        String REQUEST_ID = "_" + UUID.randomUUID().toString();
        String body;

        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter =
                new DateTime(issueInstant.getMillis() + (long) 60 * 1000);

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(ISSUER_ID);
        issuer.setFormat(NameIDType.ENTITY);

        AssertionIDRef assertionIDRef = new AssertionIDRefBuilder().buildObject();
        assertionIDRef.setAssertionID(ASSERTION_ID);

        AssertionIDRequest idRequest = new AssertionIDRequestBuilder().buildObject();
        idRequest.setVersion(SAMLVersion.VERSION_20);
        idRequest.setID(REQUEST_ID);
        idRequest.setIssueInstant(issueInstant);
        idRequest.setIssuer(issuer);
        idRequest.getAssertionIDRefs().add(assertionIDRef);

        SAMLQueryRequestUtil.doBootstrap();

        OpenSAML3Util.setSSOSignature(idRequest, DIGEST_METHOD_ALGO,
                SIGNING_ALGO, new SPSignKeyDataHolder());

        try {
            body = SAMLQueryRequestUtil.marshall(idRequest);
            System.out.println("----Sample AssertionIDRequest  Message----\n" + body);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new IdentitySAML2QueryException("Error while marshalling the request.", e);
        }

        String trustStore = (new File("")).getAbsolutePath() + File.separator + "src" + File.separator +
                "test" + File.separator + "resources" + File.separator + TRUST_STORE;

        /*
           Setting trust store. This is required if you are using SSL (HTTPS) transport WSO2
           Carbon server's certificate must be in the trust store file that is defined below
           You need to set this for security scenario 01.
         */

        System.setProperty("javax.net.ssl.trustStore", trustStore);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUST_STORE_PASSWORD);

        /*
           Creating axis2 configuration using repo that we defined and using default axis2.xml. If
           you want to use a your own axis2.xml, please configure the location for it with out
           passing null.
         */

        ConfigurationContext configurationContext;
        ServiceClient serviceClient;

        try {
            configurationContext = ConfigurationContextFactory.
                    createConfigurationContextFromFileSystem(null, null);
            serviceClient = new ServiceClient(configurationContext, null);

        } catch (AxisFault axisFault) {
            log.error("Error creating axis2 service client !!! " + axisFault);
            throw new IdentitySAML2QueryException("Error creating axis2 service client", axisFault);
        }

        Options options = new Options();
        // Security scenario 01 must use the SSL.  So we need to call HTTPS endpoint of the service.
        options.setTo(new EndpointReference(END_POINT));
        // Set the operation that you are calling in the service.
        options.setAction(SOAP_ACTION);
        // Set above options to service client.
        serviceClient.setOptions(options);

        // Set message to service.
        OMElement result;
        try {
            result = serviceClient.sendReceive(AXIOMUtil.stringToOM(body));
            System.out.println("Message is sent");
        } catch (AxisFault axisFault) {
            log.error("Error invoking service !!! " + axisFault);
            throw new IdentitySAML2QueryException("Error invoking service", axisFault);
        } catch (Exception e) {
            log.error("Error invoking service !!! " + e);
            throw new IdentitySAML2QueryException("Error invoking service", e);
        }

        // printing return message.
        if (result != null) {
            log.info("------Response Message From WSO2 Identity Server-----\n" + result.toString());
            System.out.println("------Response Message From WSO2 Identity Server-----\n" + result.toString());
        } else {
            log.error("Response message is null");
            throw new IdentitySAML2QueryException("Response message is null");
        }

        System.exit(0);
    }
}
