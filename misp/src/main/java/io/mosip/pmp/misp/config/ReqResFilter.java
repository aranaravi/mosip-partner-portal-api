package io.mosip.pmp.misp.config;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * @author Nagarjuna Kuchi
 * @version 1.0
 *
 */

public class ReqResFilter implements Filter {

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	/**
	 *  The doFilter method of the Filter is called by the container each time a request/response pair is passed through the 
	 *  chain due to a client request for a resource at the end of the chain. The FilterChain passed in to this method allows the 
	 *  Filter to pass on the request and response to the next entity in the chain.
	 *    
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		HttpServletResponse httpServletResponse = (HttpServletResponse) response;
		
		ContentCachingRequestWrapper requestWrapper = null;
		ContentCachingResponseWrapper responseWrapper = null;	

		if (httpServletRequest.getRequestURI().endsWith(".stream")) {
			chain.doFilter(request, response);
			return;
		}
		
		requestWrapper = new ContentCachingRequestWrapper(httpServletRequest);
		responseWrapper = new ContentCachingResponseWrapper(httpServletResponse);
		
		//MispLogger.info("Request : " + request.getReader().lines().collect(Collectors.joining(System.lineSeparator())));
		
		chain.doFilter(requestWrapper, responseWrapper);
		responseWrapper.copyBodyToResponse();
	}

	@Override
	public void destroy() {
	}	
}
