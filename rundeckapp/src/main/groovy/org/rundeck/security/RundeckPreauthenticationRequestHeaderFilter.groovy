/*
 * Copyright 2018 Rundeck, Inc. (http://rundeck.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rundeck.security

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest


class RundeckPreauthenticationRequestHeaderFilter extends AbstractPreAuthenticatedProcessingFilter {
    private static final transient Logger LOG = LoggerFactory.getLogger(RundeckPreauthenticationRequestHeaderFilter.class);

    boolean enabled;
    String rolesAttribute = "REMOTE_USER_GROUPS";
    String userNameHeader = null
    String rolesHeader = null

    @Override
    void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        if(!enabled) {
            chain.doFilter(request,response)
        } else {
            addForwardedRolesToRequestAttribute((HttpServletRequest)request)
            super.doFilter(request, response, chain)
        }
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(final HttpServletRequest request) {
        String forwardedUser = request.remoteUser  //in AJP this will be set by apache
        LOG.info("Request Attribute - REMOTE_USER: " + forwardedUser);

        if(userNameHeader != null && !userNameHeader.trim().isEmpty()) {
            forwardedUser = request.getHeader(userNameHeader)
            LOG.info("Request Header " + userNameHeader + ": " + forwardedUser);
        }

        LOG.info("Forwarded User: " + forwardedUser);
        return forwardedUser
    }

    @Override
    protected Object getPreAuthenticatedCredentials(final HttpServletRequest request) {
        return addForwardedRolesToRequestAttribute(request)
    }

    private Object addForwardedRolesToRequestAttribute(final HttpServletRequest request) {
        String forwardedRoles = request.getAttribute(rolesAttribute)
        LOG.info("Request Attribute - " + rolesAttribute + ": " + forwardedRoles);

        if(rolesAttribute != null && rolesHeader != null && !rolesHeader.trim().isEmpty()) {
            // Get the roles sent by the proxy and add them onto the request as an attribute for
            // PreauthenticatedAttributeRoleSource
            forwardedRoles = request.getHeader(rolesHeader);
            request.setAttribute(rolesAttribute, forwardedRoles);
            LOG.info("Request Header " + rolesHeader + ": " + forwardedRoles);
        }

        LOG.info("Forwarded Roles: " + forwardedRoles);
        return forwardedRoles
    }
}

