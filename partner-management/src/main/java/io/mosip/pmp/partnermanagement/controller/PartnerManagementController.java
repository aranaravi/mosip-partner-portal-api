package io.mosip.pmp.partnermanagement.controller;

import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.pmp.partnermanagement.core.RequestWrapper;
import io.mosip.pmp.partnermanagement.core.ResponseWrapper;
import io.mosip.pmp.partnermanagement.dto.ActivateDeactivatePartnerRequest;
import io.mosip.pmp.partnermanagement.dto.ApikeyRequests;
import io.mosip.pmp.partnermanagement.dto.PartnerAPIKeyRequestsResponse;
import io.mosip.pmp.partnermanagement.dto.PartnerAPIKeyToPolicyMappingsResponse;
import io.mosip.pmp.partnermanagement.dto.PartnersPolicyMappingRequest;
import io.mosip.pmp.partnermanagement.dto.PartnersPolicyMappingResponse;
import io.mosip.pmp.partnermanagement.dto.RetrievePartnerDetailsResponse;
import io.mosip.pmp.partnermanagement.dto.RetrievePartnersDetails;
import io.mosip.pmp.partnermanagement.service.PartnerManagementService;

/**
 * <p>This is the MOSIP Partner Management Service controller. This defines all the necessary operations</p>
 * 1.Partner ApiKey To Policy Mappings{{@link #PartnerApiKeyToPolicyMappings(RequestWrapper, String, String)} <br/>.
 * 2.Activate Deactivate AuthEKYC Partners{{@link #activateDeactivateAuthEKYCPartners(String, RequestWrapper)} <br/>.
 * 3.Activate Deactivate Partner APIKey for Given Partner{{@link #activateDeactivatePartnerAPIKeyGivenPartner(String, RequestWrapper, String)} <br/>.
 * 4.Approve or Reject Partner APIKey Requests Based On APIKeyRequestId{{@link #approveRejectPartnerAPIKeyRequestsBasedOnAPIKeyRequestId(RequestWrapper, String)} <br/>.
 * 5.Get All Auth EKYC Partners For PolicyGroup{{@link #getAllAuthEKYCPartnersForThePolicyGroup()} <br/>.
 * 6.Get particular Auth EKYC PartnerDetails For GivenPartnerId{{@link #getparticularAuthEKYCPartnerDetailsForGivenPartnerId(String)}<br/>.
 * 7.Get Partner APIKey To PolicyMappings{{@link #getPartnerAPIKeyToPolicyMappings(String, String)} <br/>.
 * 8.Get All Partner APIKey Requests As Received By PartnerManager{{@link #getAllPartnerAPIKeyRequestsAsReceivedByPartnerManager()}  <br/>.
 * 9.Get Request For Partner APIKey To PolicyMappings For GivenRequestId{{@link #getTheRequestForPartnerAPIKeyToPolicyMappingsForGivenRequestId(String)} <br/>.
 *
 * @author sanjeev.shrivastava
 *
 */

@RestController
@RequestMapping(value = "/pmpartners")
public class PartnerManagementController {

	@Autowired
	PartnerManagementService partnerManagementService;

	/**
	 * This API would be used by partner Manager, to update Partner api key to Policy Mappings.
	 * @param request 
	 * @param partnerID
	 * @param partnerAPIKey
	 * @return partnersPolicyMappingResponse.
	 */
	@RequestMapping(value = "/{partnerID}/{partnerAPIKey}", method = RequestMethod.POST)
	public ResponseEntity<ResponseWrapper<PartnersPolicyMappingResponse>> PartnerApiKeyToPolicyMappings(
			@RequestBody @Valid RequestWrapper<PartnersPolicyMappingRequest> request, 
			@PathVariable String partnerID,
			@PathVariable String partnerAPIKey) {
		PartnersPolicyMappingRequest partnersPolicyMappingRequest = request.getRequest();
		ResponseWrapper<PartnersPolicyMappingResponse> response = new ResponseWrapper<PartnersPolicyMappingResponse>();
		PartnersPolicyMappingResponse partnersPolicyMappingResponse=null;
		response.setId(request.getId());
		response.setVersion(request.getVersion());
		partnersPolicyMappingResponse = partnerManagementService
				.partnerApiKeyPolicyMappings(partnersPolicyMappingRequest, partnerID, partnerAPIKey);
		response.setResponse(partnersPolicyMappingResponse);
		return new ResponseEntity<ResponseWrapper<PartnersPolicyMappingResponse>>(response, HttpStatus.CREATED);
	}
	
	/**
	 * This API would be used to activate/deactivate Auth/E-KYC Partners
	 * @param partnerID
	 * @param request
	 * @return partnersPolicyMappingResponse.
	 */
	
	@RequestMapping(value = "/{partnerID}", method = RequestMethod.PUT)
	 public ResponseEntity<ResponseWrapper<PartnersPolicyMappingResponse>> activateDeactivateAuthEKYCPartners(
			 @PathVariable String partnerID,
			 @RequestBody @Valid RequestWrapper<ActivateDeactivatePartnerRequest> request){
		ResponseWrapper<PartnersPolicyMappingResponse> response = new ResponseWrapper<PartnersPolicyMappingResponse>();
		PartnersPolicyMappingResponse partnersPolicyMappingResponse = null;
		response.setId(request.getId());
		response.setVersion(request.getVersion());
		ActivateDeactivatePartnerRequest activateDeactivatePartnerRequest = request.getRequest();
		partnersPolicyMappingResponse = partnerManagementService
				.activateDeactivateAuthEKYCPartner(partnerID,activateDeactivatePartnerRequest);
		response.setResponse(partnersPolicyMappingResponse);
		return new ResponseEntity<ResponseWrapper<PartnersPolicyMappingResponse>>(response, HttpStatus.OK);
	 }
	
	/**
	 * Partner Manager would be using this API to activate OR de-activate PartnerAPIKey for given partner.
	 * @param partnerID
	 * @param request
	 * @param PartnerAPIKey
	 * @return partnersPolicyMappingResponse.
	 */
	
	@RequestMapping(value = "/{partnerID}/{PartnerAPIKey}", method = RequestMethod.PUT)
	public ResponseEntity<ResponseWrapper<PartnersPolicyMappingResponse>> activateDeactivatePartnerAPIKeyGivenPartner(
			@PathVariable String partnerID,
			@RequestBody @Valid RequestWrapper<ActivateDeactivatePartnerRequest> request,
			@PathVariable String PartnerAPIKey){
		ResponseWrapper<PartnersPolicyMappingResponse> response = new ResponseWrapper<PartnersPolicyMappingResponse>();
		PartnersPolicyMappingResponse partnersPolicyMappingResponse = null;
		response.setId(request.getId());
		response.setVersion(request.getVersion());
		ActivateDeactivatePartnerRequest activateDeactivatePartnerRequest = request.getRequest();
		partnersPolicyMappingResponse = partnerManagementService
				.activateDeactivatePartnerAPIKeyGivenPartner(partnerID,activateDeactivatePartnerRequest,PartnerAPIKey);
		response.setResponse(partnersPolicyMappingResponse);
		return new ResponseEntity<ResponseWrapper<PartnersPolicyMappingResponse>>(response, HttpStatus.OK);
	}
	
	/**
	 * Partner Manager would be using this API to approve OR reject partner API key
	 * requests based on API key request id. During approval process of the request
	 * unique PartnerAPI Key is generated in Partner Management module, which is
	 * mapped to requested policies. Partner API Key would be having default active
	 * status, expiry of which would configurable.
	 * 
	 * @param request
	 * @param APIKeyReqID
	 * @return partnersPolicyMappingResponse.
	 */
	@RequestMapping(value = "/PartnerAPIKeyRequests/{APIKeyReqID}", method = RequestMethod.PUT)
	public ResponseEntity<ResponseWrapper<PartnersPolicyMappingResponse>> approveRejectPartnerAPIKeyRequestsBasedOnAPIKeyRequestId(
			@RequestBody @Valid RequestWrapper<ActivateDeactivatePartnerRequest> request,
			@PathVariable String APIKeyReqID){
		ResponseWrapper<PartnersPolicyMappingResponse> response = new ResponseWrapper<PartnersPolicyMappingResponse>();
		PartnersPolicyMappingResponse partnersPolicyMappingResponse = null;
		response.setId(request.getId());
		response.setVersion(request.getVersion());
		ActivateDeactivatePartnerRequest activateDeactivatePartnerRequest = request.getRequest();
		partnersPolicyMappingResponse = partnerManagementService
				.approveRejectPartnerAPIKeyRequestsBasedOnAPIKeyRequestId(activateDeactivatePartnerRequest,APIKeyReqID);
		response.setResponse(partnersPolicyMappingResponse);
		return new ResponseEntity<ResponseWrapper<PartnersPolicyMappingResponse>>(response, HttpStatus.OK);
	}
	

	
	/** 
	 * This API would be used to retrieve all Auth/E-KYC Partners for the policy group.
	 * @return retrievePartnerDetailsResponse.
	 */
	
	@RequestMapping(value="", method = RequestMethod.GET)
	public ResponseEntity<ResponseWrapper<RetrievePartnerDetailsResponse>> getAllAuthEKYCPartnersForThePolicyGroup(){
		ResponseWrapper<RetrievePartnerDetailsResponse> response=new ResponseWrapper<RetrievePartnerDetailsResponse>();
		RetrievePartnerDetailsResponse retrievePartnerDetailsResponse = null;
		retrievePartnerDetailsResponse = partnerManagementService.getAllAuthEKYCPartnersForThePolicyGroup();
		response.setId("mosip.partnermanagement.partners.retrieve");
		response.setVersion("1.0");
		response.setResponse(retrievePartnerDetailsResponse);
		return new ResponseEntity<ResponseWrapper<RetrievePartnerDetailsResponse>>(response, HttpStatus.OK);
	}
	
	/**
	 * This API would be used to retrieve the particular Auth/E-KYC Partner details for given partner id.
	 * @param partnerID
	 * @return retrievePartnersDetails.
	 */
	
	@RequestMapping(value="/{partnerID}", method = RequestMethod.GET)
	public ResponseEntity<ResponseWrapper<RetrievePartnersDetails>> getparticularAuthEKYCPartnerDetailsForGivenPartnerId(
			@PathVariable String partnerID){
		ResponseWrapper<RetrievePartnersDetails> response = new ResponseWrapper<RetrievePartnersDetails>();
		RetrievePartnersDetails retrievePartnersDetails = null;
		retrievePartnersDetails = partnerManagementService.getparticularAuthEKYCPartnerDetailsForGivenPartnerId(partnerID);
		response.setId("mosip.partnermanagement.partners.retrieve");
		response.setVersion("1.0");
		response.setResponse(retrievePartnersDetails);
		return new ResponseEntity<ResponseWrapper<RetrievePartnersDetails>>(response , HttpStatus.OK);
	}
	
	/**
	 * Partner managers would be using this request to retrieve the Partner API key
	 * to Policy Mappings. Partner management system would be able to validate
	 * Partner API Key pattern, validate expiry for Partner API Key and status
	 * details in background, while fetching Policy to Partner API mappings.
	 * 
	 * @param partnerID
	 * @param PartnerAPIKey
	 * @return partnerAPIKeyToPolicyMappingsResponse.
	 */
	
	@RequestMapping(value = "/{partnerID}/{PartnerAPIKey}" , method = RequestMethod.GET)
	public ResponseEntity<ResponseWrapper<PartnerAPIKeyToPolicyMappingsResponse>> getPartnerAPIKeyToPolicyMappings(
			@PathVariable String partnerID,
			@PathVariable String PartnerAPIKey){
		ResponseWrapper<PartnerAPIKeyToPolicyMappingsResponse> response = new ResponseWrapper<PartnerAPIKeyToPolicyMappingsResponse>();
		PartnerAPIKeyToPolicyMappingsResponse partnerAPIKeyToPolicyMappingsResponse = null;
		partnerAPIKeyToPolicyMappingsResponse = partnerManagementService.getPartnerAPIKeyToPolicyMapping(partnerID,PartnerAPIKey);
		response.setId("mosip.partnermanagement.partners.retrieve.policy");
		response.setVersion("1.0");
		response.setResponse(partnerAPIKeyToPolicyMappingsResponse);
		return new ResponseEntity<ResponseWrapper<PartnerAPIKeyToPolicyMappingsResponse>>(response , HttpStatus.OK);
	}
	
	/**
	 * This API would be used to retrieve all Partner API Key requests as received by partner manager.
	 * @return partnerAPIKeyRequestsResponse.
	 */
	
	@RequestMapping(value = "/PartnerAPIKeyRequests" , method = RequestMethod.GET)
	public ResponseEntity<ResponseWrapper<PartnerAPIKeyRequestsResponse>> getAllPartnerAPIKeyRequestsAsReceivedByPartnerManager(){
		List<ApikeyRequests> apikeyRequests = null;
		ResponseWrapper<PartnerAPIKeyRequestsResponse> response = new ResponseWrapper<PartnerAPIKeyRequestsResponse>();
		PartnerAPIKeyRequestsResponse partnerAPIKeyRequestsResponse = new PartnerAPIKeyRequestsResponse();
		apikeyRequests = partnerManagementService.getAllPartnerAPIKeyRequestsAsReceivedByPartnerManagers();
		partnerAPIKeyRequestsResponse.setApikeyRequests(apikeyRequests);
		response.setId("mosip.partnermanagement.partners.apikey.request.retrieve");
		response.setVersion("1.0");
		response.setResponse(partnerAPIKeyRequestsResponse);
		return new ResponseEntity<ResponseWrapper<PartnerAPIKeyRequestsResponse>>(response , HttpStatus.OK);
	}
	
	/**
	 * This API would be used to retrieve the request for Partner API key to Policy Mappings for given request id.
	 * @param APIKeyReqID
	 * @return apikeyRequests.
	 */
	@RequestMapping(value = "/PartnerAPIKeyRequests/{APIKeyReqID}" , method = RequestMethod.GET)
	public ResponseEntity<ResponseWrapper<ApikeyRequests>> getTheRequestForPartnerAPIKeyToPolicyMappingsForGivenRequestId(
			@PathVariable String APIKeyReqID) {
		
		ResponseWrapper<ApikeyRequests> response = new ResponseWrapper<ApikeyRequests>();
		ApikeyRequests apikeyRequests=null;
		apikeyRequests = partnerManagementService.getTheRequestForPartnerAPIKeyToPolicyMappingsForGivenRequestId(APIKeyReqID);
		response.setId("mosip.partnermanagement.partners.apikey.requests.retrieve");
		response.setVersion("1.0");
		response.setResponse(apikeyRequests);
		return new ResponseEntity<ResponseWrapper<ApikeyRequests>>(response , HttpStatus.OK);
	}
}
