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

package org.wso2.carbon.identity.query.saml.test;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.identity.query.saml.util.OpenSAML3Util;

import java.io.File;
import java.util.UUID;


public class AuthnQueryAuthContextClient {

    private static final String END_POINT = "https://localhost:9443/services/SAMLQueryService";
    private static final String SOAP_ACTION = "http://wso2.org/identity/saml/query";
    private static final String DIGEST_METHOD_ALGO = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private static final String SIGNING_ALGO = "http://www.w3.org/2000/09/xmldsig#sha1";
    private static final String TRUST_STORE = "client-truststore.jks";
    private static final String TRUST_STORE_PASSWORD = "wso2carbon";
    private static final String ISSUER_ID = "travelocity.com";
    private static final String NAME_ID = "admin";
    private static final String SESSION_INDEX = "b6d2b2ff-ca11-4727-91d0-ec2a60be892d";
    private static final String AUTH_CONTEXT_CLASS_REF = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";

    public static void main(String[] ags) throws Exception {
        String REQUEST_ID = "_" + UUID.randomUUID().toString();
        String body = "";
        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter =
                new DateTime(issueInstant.getMillis() + (long) 60 * 1000);

        AuthnQuery authnQuery = new AuthnQueryBuilder().buildObject();
        Issuer issuer = new IssuerBuilder().buildObject();
        Subject subject = new SubjectBuilder().buildObject();
        NameID nameID = new NameIDBuilder().buildObject();
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        SubjectConfirmationData subjectConfirmationData =
                new SubjectConfirmationDataBuilder().buildObject();
        issuer.setValue(ISSUER_ID);
        issuer.setFormat(NameIDType.ENTITY);
        nameID.setValue(NAME_ID);
        nameID.setFormat(NameIdentifier.EMAIL);
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        subject.setNameID(nameID);
        authnQuery.setVersion(SAMLVersion.VERSION_20);
        authnQuery.setID(REQUEST_ID);
        authnQuery.setIssueInstant(issueInstant);
        authnQuery.setIssuer(issuer);
        authnQuery.setSubject(subject);
        RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setAuthnContextClassRef(AUTH_CONTEXT_CLASS_REF);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
        authnQuery.setRequestedAuthnContext(requestedAuthnContext);
        authnQuery.setSessionIndex(SESSION_INDEX);
        SAMLQueryRequestUtil.doBootstrap();
        OpenSAML3Util.setSSOSignature(authnQuery, DIGEST_METHOD_ALGO,
                SIGNING_ALGO, new SPSignKeyDataHolder());

        try {
            String requestMessage = SAMLQueryRequestUtil.marshall(authnQuery);
            body = requestMessage;
            System.out.println("----Sample AuthnQuery Request Message----");
            System.out.println(body);
        } catch (Exception e) {

        }


        String trustStore = (new File("")).getAbsolutePath() + File.separator + "src" + File.separator +
                "test" + File.separator + "resources" + File.separator + TRUST_STORE;



        // Setting trust store.  This is required if you are using SSL (HTTPS) transport
        // WSO2 Carbon server's certificate must be in the trust store file that is defined below
        // You need to set this for security scenario 01

        System.setProperty("javax.net.ssl.trustStore", trustStore);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUST_STORE_PASSWORD);


        // creating axis2 configuration using repo that we defined and using default axis2.xml.
        // if you want to use a your own axis2.xml, please configure the location for it with out
        // passing null

        ConfigurationContext configurationContext = null;
        ServiceClient serviceClient = null;

        try {
            configurationContext = ConfigurationContextFactory.
                    createConfigurationContextFromFileSystem(null, null);
            serviceClient = new ServiceClient(configurationContext, null);

        } catch (AxisFault axisFault) {
            System.err.println("Error creating axis2 service client !!!");
            axisFault.printStackTrace();
            System.exit(0);
        }

        Options options = new Options();

        // security scenario 01 must use the SSL.  So we need to call HTTPS endpoint of the service


        options.setTo(new EndpointReference(END_POINT));


        // set the operation that you are calling in the service.

        options.setAction(SOAP_ACTION);

        // set above options to service client
        serviceClient.setOptions(options);

        // set message to service
        OMElement result = null;
        try {
            result = serviceClient.sendReceive(AXIOMUtil.stringToOM(body));
            System.out.println("Message is sent");
        } catch (AxisFault axisFault) {
            System.err.println("Error invoking service !!!");
            axisFault.printStackTrace();
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // printing return message.
        if (result != null) {
            System.out.println("------Response Message From WSO2 Identity Server-----");
            System.out.println(result.toString());
        } else {

            System.out.println("ERROR");
        }
        System.exit(0);

    }

}
