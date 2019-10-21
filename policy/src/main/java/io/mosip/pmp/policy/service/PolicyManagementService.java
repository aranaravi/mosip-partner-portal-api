package io.mosip.pmp.policy.service;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.mosip.pmp.policy.dto.AllowedKycDto;
import io.mosip.pmp.policy.dto.AuthPolicyCreateResponseDto;
import io.mosip.pmp.policy.dto.AuthPolicyDto;
import io.mosip.pmp.policy.dto.PoliciesDto;
import io.mosip.pmp.policy.dto.PolicyCreateRequestDto;
import io.mosip.pmp.policy.dto.PolicyCreateResponseDto;
import io.mosip.pmp.policy.dto.PolicyDto;
import io.mosip.pmp.policy.dto.PolicyStatusUpdateRequestDto;
import io.mosip.pmp.policy.dto.PolicyStatusUpdateResponseDto;
import io.mosip.pmp.policy.dto.PolicyUpdateRequestDto;
import io.mosip.pmp.policy.dto.PolicyUpdateResponseDto;
import io.mosip.pmp.policy.dto.ResponseWrapper;
import io.mosip.pmp.policy.entity.AuthPolicy;
import io.mosip.pmp.policy.entity.PolicyGroup;
import io.mosip.pmp.policy.errorMessages.ErrorMessages;
import io.mosip.pmp.policy.errorMessages.PolicyManagementServiceException;
import io.mosip.pmp.policy.repository.AuthPolicyRepository;
import io.mosip.pmp.policy.repository.PolicyGroupRepository;

/**
 * <p>This class manages business logic before or after performing database operations.</p>
 * This class is performing following operations.</br>
 * 1. Creating the policy group {@link #createPolicyGroup(PolicyCreateRequestDto)} </br>
 * 2. Creating the auth policies {@link #createAuthPolicies(PolicyDto)} </br>
 * 3. Updating the policy group {@link #update(PolicyUpdateRequestDto)} </br>
 * 4. Updating the policy status {@link #updatePolicyStatus(PolicyStatusUpdateRequestDto)} </br>
 * 5. Reading/Getting the policy details {@link #getPolicyDetails(String)} </br>
 * 
 * @author Nagarjuna Kuchi
 * @version 1.0
 */

@Service
public class PolicyManagementService {

	@Autowired
	private AuthPolicyRepository authPolicyRepository;

	@Autowired
	private PolicyGroupRepository policyGroupRepository;
	
	@Value("${pmp.policy.file.storage.path}")
	private String filePath;
	

	/**
	 * <p> This function inserts the policy group data into policy group table.</p>
	 * <p> Checks the database for uniqueness of policy group name.</p>
	 * <p> If policy group name exists throws the exception saying policy group name exists.</p>
	 * <p> else will insert the data into policy group table.</p>
	 * <p> and returns the response;
	 * @param createRequestDto {@link PolicyCreateRequestDto } Contains input request details.
	 * @return response {@link PolicyCreateResponseDto } Contains response details.
	 * @throws Exception
	 */	
	public ResponseWrapper<PolicyCreateResponseDto> createPolicyGroup(PolicyCreateRequestDto createRequestDto) throws PolicyManagementServiceException,
	Exception {		
		ResponseWrapper<PolicyCreateResponseDto> response = new ResponseWrapper<>();		
		PolicyCreateResponseDto responseDto = new PolicyCreateResponseDto();
		
		response.setResponse(null);
		
		PolicyGroup policyGroupInput = new PolicyGroup();
		
		PolicyGroup policyGroupName = policyGroupRepository.findByName(createRequestDto.getName());
	
		if(policyGroupName != null){
			throw new PolicyManagementServiceException(ErrorMessages.POLICY_NAME_DUPLICATE_EXCEPTION.getErrorCode(),
					ErrorMessages.POLICY_NAME_DUPLICATE_EXCEPTION.getErrorMessage() +" " + createRequestDto.getName());
			
		}
		
		if (createRequestDto != null) {
			policyGroupInput.setName(createRequestDto.getName());
			policyGroupInput.setDescr(createRequestDto.getDesc());
			policyGroupInput.setId(policyGroupRepository.count() + "1");
			policyGroupInput.setCrBy("SYSTEM");
			policyGroupInput.setCrDtimes(LocalDateTime.now());
			policyGroupInput.setIsActive(true);
			try {
				policyGroupInput = policyGroupRepository.save(policyGroupInput);
			}			
			catch (Exception e) {
				throw new PolicyManagementServiceException(ErrorMessages.INTERNAL_SERVER_ERROR.getErrorCode(),
						ErrorMessages.INTERNAL_SERVER_ERROR.getErrorMessage(), e);
			}

		}
		
		responseDto.setIs_Active(policyGroupInput.getIsActive());
		responseDto.setId(policyGroupInput.getId());
		responseDto.setName(policyGroupInput.getName());
		responseDto.setDesc(policyGroupInput.getDescr());
		responseDto.setCr_by(policyGroupInput.getCrBy());
		responseDto.setCr_dtimes(policyGroupInput.getCrDtimes());
		responseDto.setUp_by(policyGroupInput.getUpdBy());
		responseDto.setUpd_dtimes(policyGroupInput.getUpdDtimes());
		response.setResponse(responseDto);
		
		return response;

	}
	
	/**
	 * <p> This function creates auth policies for policy group.</p>
	 * <p> Validates the policy group id.</p>
	 * <p> If policy details not found for policy id, then throws exception.</p>
	 * <p> Validates the auth policy name.</p>
	 * <p> If name exists then throws exception saying duplicate name.</p>
	 * <p> With input data will create policy document and stores in configured path.</p>
	 * <p> Saves the data into auth policy table.</p>
	 * <p> And returns the response</p>
	 * 
	 * @param policyDto {@link PolicyDto} Contains input information regarding auth policies. 
	 * @return response {@link AuthPolicyCreateResponseDto} Contains auth policies information.
	 * @throws PolicyManagementServiceException Compile time exceptions
	 * @throws Exception runtime exceptions.
	 */
	public ResponseWrapper<AuthPolicyCreateResponseDto> createAuthPolicies(PolicyDto policyDto) throws PolicyManagementServiceException, Exception
	{
		ResponseWrapper<AuthPolicyCreateResponseDto> response = new ResponseWrapper<>();	
		AuthPolicyCreateResponseDto responseDto = new AuthPolicyCreateResponseDto();
		String policyId = policyDto.getPolicyId();
		
		Optional<PolicyGroup> policyGroupDetails = policyGroupRepository.findById(policyId);		
		
		if(policyGroupDetails.get() == null)
		{
           throw new PolicyManagementServiceException(ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorCode(),
        		   ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorMessage());
		}	
		
		AuthPolicy authPolicyByName = authPolicyRepository.findByName(policyDto.getName());
		
		if(authPolicyByName != null){
			throw new PolicyManagementServiceException(ErrorMessages.AUTH_POLICY_NAME_DUPLICATE_EXCEPTION.getErrorCode(),
					ErrorMessages.AUTH_POLICY_NAME_DUPLICATE_EXCEPTION.getErrorMessage() + " " + policyDto.getName());			
		}
		
		AuthPolicy authPolicy = new AuthPolicy();
		
		authPolicy.setCrBy("SYSTEM");
		authPolicy.setId(authPolicyRepository.count() + "1");
		authPolicy.setCrDtimes(LocalDateTime.now());
		authPolicy.setDescr(policyDto.getDescr());
		authPolicy.setName(policyDto.getName());
		authPolicy.setIsActive(true);
		authPolicy.setIsDeleted(false);		
		authPolicy.setPolicyFileId(createPolicyFile(policyDto,policyDto.getName()));
		authPolicy.setPolicyGroup(policyGroupDetails.get());		
		
		try {
			authPolicy = authPolicyRepository.save(authPolicy);
		}			
		catch (Exception e) {
			throw new PolicyManagementServiceException(ErrorMessages.INTERNAL_SERVER_ERROR.getErrorCode(),
					ErrorMessages.INTERNAL_SERVER_ERROR.getErrorMessage(), e);
		}
		
		responseDto.set_Active(authPolicy.getIsActive());
		responseDto.setId(authPolicy.getId());
		responseDto.setName(authPolicy.getName());
		responseDto.setDesc(authPolicy.getDescr());
		responseDto.setCr_by(authPolicy.getCrBy());
		responseDto.setCr_dtimes(authPolicy.getCrDtimes());
		responseDto.setUp_by(authPolicy.getUpdBy());
		responseDto.setUpd_dtimes(authPolicy.getUpdDtimes());
		
		response.setResponse(responseDto);
		return response;
	}

	/**
	 * <p>This function updates the policy group details along with auth policies.</p>
	 * <p> </p>
	 * @param updateRequestDto
	 * @return
	 * @throws Exception
	 */
	
	public ResponseWrapper<PolicyUpdateResponseDto> update(PolicyUpdateRequestDto updateRequestDto) 
			throws Exception {
		
		PolicyGroup policyGroup = policyGroupRepository.findByName(updateRequestDto.getName());
		if(policyGroup!=null && !policyGroup.getId().equals(updateRequestDto.getId()))
		{
			throw new PolicyManagementServiceException(ErrorMessages.POLICY_NAME_DUPLICATE_EXCEPTION.getErrorCode(),
					ErrorMessages.POLICY_NAME_DUPLICATE_EXCEPTION.getErrorMessage() +" " + updateRequestDto.getName());
		}
		
		Optional<PolicyGroup> policyGroupDetails = policyGroupRepository.findById(updateRequestDto.getId());
		if(!policyGroupDetails.isPresent())
		{
           throw new PolicyManagementServiceException(ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorCode(),
        		   ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorMessage());
		}
		
		ResponseWrapper<PolicyUpdateResponseDto> response = new ResponseWrapper<>();	
		PolicyUpdateResponseDto responseDto = new PolicyUpdateResponseDto();
		PolicyGroup policyGroupFromDb = null;
		if (policyGroupDetails != null && policyGroupDetails.get() != null){
			policyGroupFromDb = policyGroupDetails.get();
			policyGroupFromDb.setName(updateRequestDto.getName());
			policyGroupFromDb.setDescr(updateRequestDto.getDesc());
			policyGroupFromDb.setId(policyGroupDetails.get().getId());
			policyGroupFromDb.setCrBy("SYSTEM");
			policyGroupFromDb.setCrDtimes(LocalDateTime.now());
			policyGroupFromDb.setIsActive(true);
			policyGroupFromDb.setUpdDtimes(LocalDateTime.now());
			policyGroupFromDb.setUpdBy("SYSTEM");

			policyGroupFromDb = policyGroupRepository.save(policyGroupFromDb);
		}
		
		updateRequestDto.getPolicies().setPolicyId(policyGroupFromDb.getId());
		updateRequestDto.getPolicies().setName(policyGroupFromDb.getName());
		updateRequestDto.getPolicies().setDescr(policyGroupFromDb.getName());
		
		createAuthPolicies(updateRequestDto.getPolicies());
		
		responseDto.set_Active(policyGroupFromDb.getIsActive());
		responseDto.setId(policyGroupFromDb.getId());
		responseDto.setName(policyGroupFromDb.getName());
		responseDto.setDesc(policyGroupFromDb.getDescr());
		responseDto.setCr_by(policyGroupFromDb.getCrBy());
		responseDto.setCr_dtimes(policyGroupFromDb.getCrDtimes());
		responseDto.setUp_by(policyGroupFromDb.getUpdBy());
		responseDto.setUpd_dtimes(policyGroupFromDb.getUpdDtimes());
		response.setResponse(responseDto);
		
		return response;
	}

	/**
	 * @param statusUpdateRequest
	 * @return
	 */
	public ResponseWrapper<PolicyStatusUpdateResponseDto> updatePolicyStatus(PolicyStatusUpdateRequestDto statusUpdateRequest) {
		Boolean status = statusUpdateRequest.getStatus().contains("De-Active") ? false : true;

		ResponseWrapper<PolicyStatusUpdateResponseDto> response = new ResponseWrapper<>();
		PolicyStatusUpdateResponseDto responseDto = new PolicyStatusUpdateResponseDto();
		
		Optional<PolicyGroup> policyGroupDetails = policyGroupRepository.findById(statusUpdateRequest.getId());
        if(!policyGroupDetails.isPresent()){
        	throw new PolicyManagementServiceException(ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorCode(),
        			ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorMessage());
        }
		
		
		PolicyGroup policyGroupFromDb = null;
		if (policyGroupDetails != null && policyGroupDetails.get() != null) {
			policyGroupFromDb = policyGroupDetails.get();
			policyGroupFromDb.setIsActive(status);
			policyGroupFromDb.setUpdBy("SYSTEM");
			policyGroupFromDb.setUpdDtimes(LocalDateTime.now());
			policyGroupRepository.save(policyGroupFromDb);
		}

		responseDto.setMessage("status updated successfully");
		response.setResponse(responseDto);
	 return response;	
	}

	/**
	 * @param policyId
	 * @return
	 * @throws ParseException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 */
	public List<PoliciesDto> getPolicyDetails(String policyId) throws FileNotFoundException, IOException, ParseException {
		List<PolicyGroup> policies = new ArrayList<PolicyGroup>();
		
		if (policyId != "") {
			
			Optional<PolicyGroup> policyFromDb =policyGroupRepository.findById(policyId); 
			
			if(!policyFromDb.isPresent()){
	        	throw new PolicyManagementServiceException(ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorCode(),
	        			ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorMessage());	
				
			}
			
			policies.add(policyFromDb.get());

		} else {
			policies = policyGroupRepository.findAll();			
		}

		if(policies.isEmpty()){
        	throw new PolicyManagementServiceException(ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorCode(),
        			ErrorMessages.POLICY_ID_NOT_EXISTS.getErrorMessage());	
		}
		
		List<PoliciesDto> allPolicies = new ArrayList<PoliciesDto>();		
		PoliciesDto policiesDto = new PoliciesDto();
		
		for(PolicyGroup policy : policies)
		{
			boolean isAuthPolicyExist = false;
			
			policiesDto.setPolicy(setPolicyGroup(policy));
			
			List<AuthPolicy> authPolicies = authPolicyRepository.findAll();
			List<PolicyDto> policyDtos = new ArrayList<PolicyDto>();
			
			for(AuthPolicy authPolicy : authPolicies)
			{				
				if(policy.getId() == authPolicy.getPolicyGroup().getId()){
						
					isAuthPolicyExist = true;
					PolicyDto authPolicyDto = readPolicyFile(authPolicy.getName() +".json");
					authPolicyDto.setName(authPolicy.getName());
					authPolicyDto.setDescr(authPolicy.getDescr());	
					policyDtos.add(authPolicyDto);
				}
				
			}
			
			if(isAuthPolicyExist){
			policiesDto.setAuthPolicies(policyDtos);
			}
			
			allPolicies.add(policiesDto);
		}
		
		return allPolicies;
	}

	private PolicyCreateResponseDto setPolicyGroup(PolicyGroup policy) {

		PolicyCreateResponseDto responseDto = new PolicyCreateResponseDto();
		responseDto.setIs_Active(policy.getIsActive());
		responseDto.setId(policy.getId());
		responseDto.setName(policy.getName());
		responseDto.setDesc(policy.getDescr());
		responseDto.setCr_by(policy.getCrBy());
		responseDto.setCr_dtimes(policy.getCrDtimes());
		responseDto.setUp_by(policy.getUpdBy());
		responseDto.setUpd_dtimes(policy.getUpdDtimes());
		
		return responseDto;
	}


	/**
	 * @param policy
	 * @param name
	 * @return
	 * @throws IOException
	 */
	@SuppressWarnings("unchecked")
	private String createPolicyFile(PolicyDto policy, String name) throws PolicyManagementServiceException,Exception {
		String fileName = name + ".json";

		JSONObject obj = new JSONObject();
		JSONArray authPolicies = new JSONArray();
		JSONArray allowedKycAttributes = new JSONArray();

		for (AuthPolicyDto authPolicyDto : policy.getAuthPolicies()) {
			JSONObject authObj = new JSONObject();
			authObj.put("authType", authPolicyDto.getAuthType());
			authObj.put("authSubType", authPolicyDto.getAuthSubType());
			authObj.put("mandatory", authPolicyDto.isMandatory());

			authPolicies.add(authObj);
		}

		for (AllowedKycDto allowedKycDto : policy.getAllowedKycAttributes()) {
			JSONObject allowedKycObj = new JSONObject();
			allowedKycObj.put("attributeName", allowedKycDto.getAttributeName());
			allowedKycObj.put("required", allowedKycDto.isRequired());
			allowedKycAttributes.add(allowedKycObj);
		}

		obj.put("authPolicies", authPolicies);
		obj.put("allowedKycAttributes", allowedKycAttributes);

		try (FileWriter file = new FileWriter(filePath + fileName)) {
			file.write(obj.toJSONString());
		}
		
		return fileName;
	}
	
	private PolicyDto readPolicyFile(String fileName) throws FileNotFoundException, IOException, ParseException
	{
		PolicyDto authKycDto = new PolicyDto();
		List<AllowedKycDto> authList = new ArrayList<AllowedKycDto>();
		List<AuthPolicyDto> authDtoList = new ArrayList<AuthPolicyDto>();
		

		JSONParser jsonParser = new JSONParser();
		
		
		try(FileReader reader = new FileReader(filePath + fileName)){
			
			Object obj = jsonParser.parse(reader);
			JSONObject jsonObject = (JSONObject) obj;
			JSONArray authData = (JSONArray)jsonObject.get("authPolicies");
			JSONArray allowedKycData = (JSONArray)jsonObject.get("allowedKycAttributes");		
			
			
			
			for(Object o: authData){
				AuthPolicyDto authDto = new AuthPolicyDto();
				
				JSONObject jsonObject1 = (JSONObject) o;
				authDto.setAuthType(jsonObject1.get("authType").toString());
				authDto.setAuthSubType(jsonObject1.get("authSubType") != null ? jsonObject1.get("authSubType").toString() : null);
				authDto.setMandatory(Boolean.parseBoolean(jsonObject1.get("mandatory").toString()));
				authDtoList.add(authDto);
				
            }

			
			for(Object o: allowedKycData){
				AllowedKycDto auth = new AllowedKycDto();
				JSONObject jsonObject1 = (JSONObject) o;
				auth.setAttributeName(jsonObject1.get("attributeName").toString());
				auth.setRequired(Boolean.parseBoolean(jsonObject1.get("required").toString()));
				authList.add(auth);
            }
			
			
		}catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
		
		authKycDto.setAllowedKycAttributes(authList);
		authKycDto.setAuthPolicies(authDtoList);
		return authKycDto;
	}

}
