/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.gateway.resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.api.exception.GatewayClientException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayServerException;
import org.wso2.carbon.identity.gateway.api.processor.GatewayProcessor;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequest;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequestBuilderFactory;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponseBuilderFactory;
import org.wso2.carbon.identity.gateway.resource.internal.GatewayResourceDataHolder;
import org.wso2.msf4j.Request;

import javax.ws.rs.core.Response;
import java.util.List;

public class GatewayManager {


    private Logger log = LoggerFactory.getLogger(GatewayManager.class);

    public Response execute(Request request) {


        GatewayRequestBuilderFactory factory = null ;
        GatewayRequest gatewayRequest = null;
        Response.ResponseBuilder responseBuilder = null;


        try {



            factory = getIdentityRequestFactory(request);


            try {


                gatewayRequest = factory.create(request).build();


                if (gatewayRequest == null) {
                    throw new GatewayRuntimeException("GatewayRequest is Null. Cannot proceed!!");
                }


            } catch (GatewayClientException e) {
                responseBuilder = factory.handleException(e);
                if (responseBuilder == null) {
                    throw new GatewayRuntimeException("HttpIdentityResponseBuilder is Null. Cannot proceed!!");
                }
                //#TODO Enable this to new response
                return responseBuilder.build();

            } catch (GatewayRuntimeException e){
                if(factory == null) {
                    //Use defaultFactory exception handling
                }
                responseBuilder = factory.handleException(e);
                if (responseBuilder == null) {
                    throw new GatewayRuntimeException("HttpIdentityResponseBuilder is Null. Cannot proceed!!");
                }
                //#TODO Enable this to new response
                return responseBuilder.build();

            }

            GatewayResponse gatewayResponse = null;
            GatewayResponseBuilderFactory responseFactory = null;

            GatewayProcessor processor = getIdentityProcessor(gatewayRequest);


            try {
                gatewayResponse = processor.process(gatewayRequest).build();
                if (gatewayResponse == null) {
                    throw new GatewayRuntimeException("GatewayResponse is Null. Cannot proceed!!");
                }
                responseFactory = getIdentityResponseFactory(gatewayResponse);
                Response.ResponseBuilder builder = responseFactory.createBuilder(gatewayResponse);
                if (builder == null) {
                    throw new GatewayRuntimeException("HttpIdentityResponseBuilder is Null. Cannot proceed!!");
                }
                return builder.build();


            } catch (GatewayRuntimeException e) {
                responseBuilder = factory.handleException(e);
                if (responseBuilder == null) {
                    throw new GatewayRuntimeException("HttpIdentityResponseBuilder is Null. Cannot proceed!!");
                }
                return responseBuilder.build();
            }


        } catch (Throwable exception) {
            log.error("Error occurred while processing the request in GatewayManager : " + exception);
            Response.ResponseBuilder builder = handleException(exception);
            return builder.build();
        }
    }

    public Response.ResponseBuilder handleException(Throwable exception) {

        Response.ResponseBuilder builder = Response.noContent();
        builder.status(500);
        builder.entity("Server Error: Something went wrong.");
        return builder;
    }


    private GatewayProcessor getIdentityProcessor(GatewayRequest gatewayRequest) {
        List<GatewayProcessor> processors = GatewayResourceDataHolder.getInstance().getGatewayProcessors();

        for (GatewayProcessor requestProcessor : processors) {
            try {
                if (requestProcessor.canHandle(gatewayRequest)) {
                    return requestProcessor;
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + requestProcessor.getName() + " can handle " +
                          gatewayRequest.toString());
            }
        }
        throw new GatewayRuntimeException("No GatewayProcessor found to process the request.");
    }



    private GatewayRequestBuilderFactory getIdentityRequestFactory(Request request)
            {

        List<GatewayRequestBuilderFactory> factories =
                GatewayResourceDataHolder.getInstance().getHttpIdentityRequestFactories();

        for (GatewayRequestBuilderFactory requestBuilder : factories) {
            try {
                if (requestBuilder.canHandle(request)) {
                    return requestBuilder;
                }
            } catch (GatewayClientException e) {
                e.printStackTrace();
            } catch (GatewayServerException e) {
                e.printStackTrace();
            }
        }

        throw new GatewayRuntimeException("No GatewayResponseBuilderFactory found to create the request");
    }

    private GatewayResponseBuilderFactory getIdentityResponseFactory(GatewayClientException exception) {

        List<GatewayResponseBuilderFactory> factories = GatewayResourceDataHolder.getInstance()
                .getHttpIdentityResponseFactories();

        for (GatewayResponseBuilderFactory responseFactory : factories) {
            if (responseFactory.canHandle(exception)) {
                return responseFactory;
            }
        }
        throw new GatewayRuntimeException("No GatewayResponseBuilderFactory found to create the response.");
    }


    private GatewayResponseBuilderFactory getIdentityResponseFactory(GatewayServerException exception) {

        List<GatewayResponseBuilderFactory> factories = GatewayResourceDataHolder.getInstance()
                .getHttpIdentityResponseFactories();

        for (GatewayResponseBuilderFactory responseFactory : factories) {
            if (responseFactory.canHandle(exception)) {
                return responseFactory;
            }
        }
        throw new GatewayRuntimeException("No GatewayResponseBuilderFactory found to create the response.");
    }


    private GatewayResponseBuilderFactory getIdentityResponseFactory(GatewayResponse gatewayResponse) {

        List<GatewayResponseBuilderFactory> factories = GatewayResourceDataHolder.getInstance()
                .getHttpIdentityResponseFactories();

        for (GatewayResponseBuilderFactory responseFactory : factories) {
            if (responseFactory.canHandle(gatewayResponse)) {
                return responseFactory;
            }
        }
        throw new GatewayRuntimeException("No GatewayResponseBuilderFactory found to create the response.");
    }
}
