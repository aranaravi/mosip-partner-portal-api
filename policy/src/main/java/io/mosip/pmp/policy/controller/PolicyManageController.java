package io.mosip.pmp.policy.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;

import javax.validation.Valid;

import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.pmp.policy.dto.AuthPolicyCreateResponseDto;
import io.mosip.pmp.policy.dto.PoliciesDto;
import io.mosip.pmp.policy.dto.PolicyCreateRequestDto;
import io.mosip.pmp.policy.dto.PolicyCreateResponseDto;
import io.mosip.pmp.policy.dto.PolicyDto;
import io.mosip.pmp.policy.dto.PolicyStatusUpdateRequestDto;
import io.mosip.pmp.policy.dto.PolicyStatusUpdateResponseDto;
import io.mosip.pmp.policy.dto.PolicyUpdateRequestDto;
import io.mosip.pmp.policy.dto.PolicyUpdateResponseDto;
import io.mosip.pmp.policy.dto.RequestWrapper;
import io.mosip.pmp.policy.dto.ResponseWrapper;
import io.mosip.pmp.policy.service.PolicyManagementService;
import io.swagger.annotations.Api;

/** 
 * <p> This is policy controller. This controller defines all the operations required </p>
 * <p> to manage policy group.</p>
 * <p> This controller provides following operations/functions.</p>
 *     1. Create policy group.</br>
 *     2. Create auth policies for policy group.</br> 
 *     3. Update policy group.</br>
 *     4. Update policy group status.</br>
 *     5. Read/Get all policy groups.</br>
 *     6. Read/Get specific policy group.</br>
 *     7. Read/Get policy details of a partner api key.</br>
 *       
 * @author Nagarjuna Kuchi
 * @version 1.0
 *
 */

@RestController
@RequestMapping(value = "/pmp")
@Api(tags = { " Partner Management : Policy Management Controller " })
public class PolicyManageController {

	@Autowired
	private PolicyManagementService policyManagementService;

	
	/**
	 * <p> This API would be used to create new Policy for policy group.</p>
	 * 
	 * @param createRequest {@link PolicyCreateRequestDto} this contains all the required parameters for creating the policy.
	 * @return response {@link PolicyCreateResponseDto} this contains all the response parameters for created policy.
	 * @throws Exception  
	 */
	
	@PostMapping(value = "/policies")	
	public ResponseWrapper<PolicyCreateResponseDto> definePolicy(
			@RequestBody @Valid RequestWrapper<PolicyCreateRequestDto> createRequest) throws Exception {
		
		ResponseWrapper<PolicyCreateResponseDto> response = policyManagementService.
				createPolicyGroup(createRequest.getRequest());		
		response.setId(createRequest.getId());
		response.setVersion(createRequest.getVersion());
		
		return response;
	}
	
	/**
	 * <p> This API would be used to create auth policies for existing policy.</p>
	 * 
	 * @param policyDto {@link PolicyDto} this contains all the required parameters for creating the auth policies.
	 * @param policyID policy group id
	 * @return response {@link AuthPolicyCreateResponseDto} contains all response details.
	 * @throws Exception
	 */	
	@PostMapping(value = "/policies/{policyID}/authPolicies")
	public ResponseWrapper<AuthPolicyCreateResponseDto> assignAuthPolicies(@RequestBody @Valid RequestWrapper<PolicyDto> policyDto,
			@PathVariable String policyID) throws Exception	{
		
		PolicyDto policyRequestDto = policyDto.getRequest();
		policyRequestDto.setPolicyId(policyID);
	
		ResponseWrapper<AuthPolicyCreateResponseDto> response = policyManagementService.
				createAuthPolicies(policyRequestDto);		
		response.setId(policyDto.getId());
		response.setVersion(policyDto.getVersion());
		
		return response;		
	}

	/**
	 * <p> This API would be used to update existing policy for a policy group.</p>
	 *  
	 * @param updateRequestDto {@link PolicyUpdateRequestDto } Encapsulated all the required parameters required for policy update.
	 * @param policyID policy id.
	 * @return response {@link PolicyUpdateResponseDto} contains all response details.
	 * @throws Exception
	 */
	@PostMapping(value = "/policies/{policyID}")
	public ResponseWrapper<PolicyUpdateResponseDto> updatePolicyDetails(
			@RequestBody RequestWrapper<PolicyUpdateRequestDto> updateRequestDto, @PathVariable String policyID)
			throws Exception {
		PolicyUpdateRequestDto updateRequest = updateRequestDto.getRequest();
		updateRequest.setId(policyID);
		
		ResponseWrapper<PolicyUpdateResponseDto> response = policyManagementService.update(updateRequest);
		
		response.setId(updateRequestDto.getId());
		response.setVersion(updateRequestDto.getVersion());
		
		return response;
	}

	/**
	 * <p> This API would be used to update the status (activate/deactivate) for the given policy id.</p>
	 * 
	 * @param requestDto {@link PolicyStatusUpdateRequestDto } Defines all the required parameters for policy status update.	 *  
	 * @param policyID policy id.
	 * @return response {@link PolicyStatusUpdateResponseDto} contains all response details.
	 * @throws Exception
	 */
	@PutMapping(value = "/policies/{policyID}")
	public ResponseWrapper<PolicyStatusUpdateResponseDto> updatePolicyStatus(@RequestBody RequestWrapper<PolicyStatusUpdateRequestDto> requestDto,
			@PathVariable String policyID) throws Exception {
		
		PolicyStatusUpdateRequestDto statusUpdateRequest = requestDto.getRequest();
		
		statusUpdateRequest.setId(policyID);		
		
		ResponseWrapper<PolicyStatusUpdateResponseDto> response =  policyManagementService.
				updatePolicyStatus(statusUpdateRequest);		
		response.setId(requestDto.getId());
		response.setVersion(requestDto.getVersion());

		return response;
	}

	/**
	 * <p> This API would be used to get details for the policies in the policy group he belongs to.</p>
	 * 
	 * @return response {@link PoliciesDto}  policy group associated with his auth policies.
	 * @throws ParseException  
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	@GetMapping(value = "/policies")
	public ResponseWrapper<PoliciesDto> getPolicyDetails() throws FileNotFoundException, IOException, ParseException{
		ResponseWrapper<PoliciesDto> response = new ResponseWrapper<>();
		
		List<PoliciesDto> policies = policyManagementService.getPolicyDetails("");
		response.setResponse(policies.get(0));
		
		return response;
	}

	/**
	 * <p> This API would be used to retrieve existing policy for a policy group based on the policy id.</p>
	 * 
	 * @param policyID policy id.
	 * @return response  {@link PoliciesDto}  policy group associated with his auth policies.
	 * @throws Exception
	 */
	@GetMapping(value = "/policies/{policyID}")
	public ResponseWrapper<PoliciesDto> getPolicyDetails(@PathVariable String policyID) throws Exception {
		ResponseWrapper<PoliciesDto> response = new ResponseWrapper<>();
		
		PoliciesDto policyGroup = policyManagementService.getPolicyDetails(policyID).get(0);
		response.setResponse(policyGroup);
		
		return response;
	}
	
	/**
	 * <p>This API would be used to retrieve the partner policy details for given PartnerAPIKey.</p>
	 */

}
