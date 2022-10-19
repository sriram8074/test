package com.amazonaws.kendra.connector.aem.services;

import static aemapi.AemAcl.isUser;
import static aemapi.AemAsset.getModifiedAssets;
import static aemapi.AemPage.getAemPageData;
import static aemapi.AemPage.getChangedLogPages;
import static aemapi.Constants.BASIC;
import static aemapi.Constants.JCR_TITLE;
import static aemapi.Constants.OAUTH;
import static aemapi.Constants.ZERO;
import static com.amazonaws.kendra.connector.aem.util.Constants.CLOUD;
import static com.amazonaws.kendra.connector.aem.util.Constants.DEFAULT_ASSETROOTPATH;
import static com.amazonaws.kendra.connector.aem.util.Constants.DEFAULT_PAGEROOTPATH;
import static com.amazonaws.kendra.connector.aem.util.Constants.ITEM_PRINCIPAL;
import static com.amazonaws.kendra.connector.aem.util.Constants.ONPREM;
import static com.amazonaws.kendra.connector.aem.util.Constants.DATABASE_TYPE;


import aemapi.AemAccess;
import aemapi.AemAclData;
import aemapi.AemAsset;
import aemapi.AemAssetData;
import aemapi.AemHttpClient;
import aemapi.AemPage;
import aemapi.AemPageData;
import com.amazonaws.kendra.connector.aem.model.repository.AemConfiguration;
import com.amazonaws.kendra.connector.aem.util.AemCollaborationInfo;
import com.amazonaws.kendra.connector.sdk.exception.BadRequestException;
import com.amazonaws.kendra.connector.sdk.exception.ContinuableBadRequestException;
import com.amazonaws.kendra.connector.sdk.model.item.ItemInfo;
import com.amazonaws.kendra.connector.sdk.model.item.ItemState;
import com.amazonaws.kendra.connector.sdk.model.item.ItemType;
import com.amazonaws.util.CollectionUtils;
import com.google.gson.Gson;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONException;


/**
 * Service class for AEM connector.
 *
 * @author omkar_phadtare
 */
@Slf4j
public class AemService {

	public static Map<String, InputStream> getPageItemIdInputStreamMap() {
		return pageItemIdInputStreamMap;
	}

	/**
	 * Method to test Aem server connection.
	 *
	 * @return boolean stating connection status.
	 */
	private static Map<String, InputStream> pageItemIdInputStreamMap = new HashMap<>();
	private static Map<String, InputStream> assetItemIdInputStreamMap = new HashMap<>();

	/**
	 * Method for Test connection.
	 *
	 * @param aemConfiguration input param.
	 * @return boolean stating connection status.
	 */
	public boolean testConnection(AemConfiguration aemConfiguration) {
		log.info("Connecting with AEM Server.");
		String authType = aemConfiguration.getAuthType();
		String databaseType = aemConfiguration.getDatabaseType();
		AemHttpClient.setDatabaseType(databaseType);
		String userName;
		String password;
		String clientId;
		String clientSecret;
		String privateKey;
		String orgId;
		String technicalAccountId;
		String imsHost;
		String customScopeName;
		String aemUrl = aemConfiguration.getAemUrl();
		AemAccess.setAemEndpoint(aemUrl);
		AemHttpClient.setAuthType(authType);
		try {
			if (authType.equals(BASIC)) {
				userName = aemConfiguration.getUsername();
				password = aemConfiguration.getPassword();
				AemHttpClient.setUserName(userName);
				AemHttpClient.setPassword(password);
			} else if (authType.equals(OAUTH)) {
				clientId = aemConfiguration.getClientId();
				clientSecret = aemConfiguration.getClientSecret();
				privateKey = aemConfiguration.getPrivateKey();
				AemHttpClient.setClientId(clientId);
				AemHttpClient.setClientSecret(clientSecret);
				AemHttpClient.setPrivateKey(privateKey);

				if (aemConfiguration.getDatabaseType().equals(ONPREM)) {
					AemHttpClient.createAndSetAccessToken(clientId, clientSecret, privateKey, aemUrl);
				}else if (aemConfiguration.getDatabaseType().equals(CLOUD)) {
					orgId = aemConfiguration.getOrgId();
					technicalAccountId = aemConfiguration.getTechnicalAccountId();
					imsHost = aemConfiguration.getImsHost();
					AemHttpClient.setOrgId(orgId);
					AemHttpClient.setTechnicalAccountId(technicalAccountId);
					AemHttpClient.setImsHost(imsHost);
					AemHttpClient.createAndSetCloudAccessToken(clientId, clientSecret, privateKey);	
				}
			}
		} catch (Exception e) {
			throw new BadRequestException(e.getMessage(), e);
		}
		log.info("Connected with AEM Server");
		return Boolean.TRUE;
	}

	/**
	 * Method to get ItemInfo for getAemEntities.
	 *
	 * @param aemConfiguration input param.
	 * @param timestamp        input param.
	 * @return ItemInfo Queue
	 */
	public Queue<ItemInfo> getAemEntities(AemConfiguration aemConfiguration, long timestamp) {
		Queue<ItemInfo> aemItemInfo = new ConcurrentLinkedQueue<>();
		Set<String> rootPaths = new HashSet<>();
		if (aemConfiguration.crawlPages()) {
			if (CollectionUtils.isNullOrEmpty(aemConfiguration.getPageRootPaths())) {
				rootPaths.add(DEFAULT_PAGEROOTPATH);
			} else {
				rootPaths.addAll(aemConfiguration.getPageRootPaths());
			}
			if (timestamp > ZERO) {
				aemItemInfo.addAll(getAllChangedPageItemInfo(rootPaths, aemConfiguration, timestamp));
			} else {
				aemItemInfo.addAll(getAllPageItemInfo(rootPaths, aemConfiguration));
			}
		}
		rootPaths.clear();

		if (aemConfiguration.crawlAssets()) {
			if (CollectionUtils.isNullOrEmpty(aemConfiguration.getAssetRootPaths())) {
				rootPaths.add(DEFAULT_ASSETROOTPATH);
			} else {
				rootPaths.addAll(aemConfiguration.getAssetRootPaths());
			}
			if (timestamp > ZERO) {
				aemItemInfo.addAll(getAllChangedAssetItemInfo(rootPaths, aemConfiguration, timestamp));
			} else {
				aemItemInfo.addAll(getAllAssetItemInfo(rootPaths, aemConfiguration));
			}
		}
		return aemItemInfo;
	}

	/**
	 * Method to get ItemInfo for getAllPageItemInfo.
	 *
	 * @param rootPaths        root paths list
	 * @param aemConfiguration Input param aem Configuration
	 * @return ItemInfo Queue
	 */
	private Queue<ItemInfo> getAllPageItemInfo(Set<String> rootPaths,
			AemConfiguration aemConfiguration) {
		Queue<ItemInfo> pageItemInfo = new ConcurrentLinkedQueue<>();
		try {
			AemPage.getPagePathsList(rootPaths)
			.forEach(pagePath -> {
				try {
					AemPageData aemPageData;
					if (shouldPageBeCrawled(pagePath,aemConfiguration)) {
						aemPageData = getAemPageData(pagePath, aemConfiguration);
						pageItemInfo.add(buildPageItemInfo(aemPageData));
					}
				} catch (URISyntaxException | IOException | JSONException e) {
					throw new RuntimeException(e);
				}
			});
		} catch (URISyntaxException | IOException e) {
			throw new RuntimeException(e);
		}
		return pageItemInfo;
	}

	/**
	 * Method to get ItemInfo for getAllChangedPageItemInfo.
	 *
	 * @param rootPaths        root paths Set
	 * @param aemConfiguration Input param aem Configuration
	 * @param timestamp timestamp
	 * @return ItemInfo Queue
	 */
	public Queue<ItemInfo> getAllChangedPageItemInfo(Set<String> rootPaths,
			AemConfiguration aemConfiguration, long timestamp) {
		Queue<ItemInfo> pageItemInfo = new ConcurrentLinkedQueue<>();
		try {
			getChangedLogPages(rootPaths, timestamp)
			.forEach(pagePath -> {
				try {
					AemPageData aemPageData;
					if (shouldPageBeCrawled(pagePath,aemConfiguration)) {
						aemPageData = getAemPageData(pagePath, aemConfiguration);
						pageItemInfo.add(buildPageItemInfo(aemPageData));
					}
				} catch (URISyntaxException | IOException | JSONException e) {
					throw new RuntimeException(e);
				}
			});
		} catch (URISyntaxException | IOException e) {
			throw new RuntimeException(e);
		}
		return pageItemInfo;
	}

	/**
	 * Method to get ItemInfo for getAllAssetItemInfo.
	 *
	 * @param rootPaths        root paths list
	 * @param aemConfiguration Input param aem Configuration
	 * @return ItemInfo Queue
	 */
	private Queue<ItemInfo> getAllAssetItemInfo(Set<String> rootPaths,
			AemConfiguration aemConfiguration) {
		Queue<ItemInfo> assetItemInfo = new ConcurrentLinkedQueue<>();
		try {
			AemAsset.getAssetPathsList(rootPaths)
			.forEach(assetPath -> {
				try {
					AemAssetData aemAssetData;
					if (shouldAssetBeCrawled(assetPath,aemConfiguration)) {
						aemAssetData = AemAsset.getAemAssetData(assetPath);
						assetItemInfo.add(buildAssetItemInfo(aemAssetData));
					}
				} catch (JSONException | URISyntaxException | IOException e) {
					throw new RuntimeException(e);
				}
			});
		} catch (URISyntaxException | IOException e) {
			throw new RuntimeException(e);
		}
		return assetItemInfo;
	}

	/**
	 * Method to get ItemInfo for getAllChangedAssetItemInfo.
	 *
	 * @param rootPaths        root paths Set
	 * @param aemConfiguration Input param aem Configuration
	 * @param timestamp timestamp
	 * @return ItemInfo Queue
	 */
	private Queue<ItemInfo> getAllChangedAssetItemInfo(Set<String> rootPaths,
			AemConfiguration aemConfiguration, long timestamp) {
		Queue<ItemInfo> assetItemInfo = new ConcurrentLinkedQueue<>();
		try {
			getModifiedAssets(rootPaths, timestamp)
			.forEach(assetPath -> {
				try {
					AemAssetData aemAssetData;
					if (shouldAssetBeCrawled(assetPath,aemConfiguration)) {
						aemAssetData = AemAsset.getAemAssetData(assetPath);
						assetItemInfo.add(buildAssetItemInfo(aemAssetData));
					}
				} catch (JSONException | URISyntaxException | IOException e) {
					throw new RuntimeException(e);
				}
			});
		} catch (URISyntaxException | IOException e) {
			throw new RuntimeException(e);
		}
		return assetItemInfo;
	}

	/**
	 * Method to should page be crawled based on {@link AemConfiguration}.
	 *
	 * @param pagePath input parameter.
	 * @param aemConfiguration input parameter.
	 * @return boolean
	 */
	public boolean shouldPageBeCrawled(String pagePath,
			AemConfiguration aemConfiguration) {
		if (isPageInclusionExclusionApplicable(aemConfiguration)
				&& checkForPagePathInclusionExclusion(pagePath, aemConfiguration)) {
			return Boolean.FALSE;
		}
		return Boolean.TRUE;
	}

	/**
	 * Method to should asset be crawled based on {@link AemConfiguration}.
	 *
	 * @param assetPath input parameter.
	 * @param aemConfiguration input parameter.
	 * @return boolean
	 */
	public boolean shouldAssetBeCrawled(String assetPath,
			AemConfiguration aemConfiguration) {
		if (isAssetPathInclusionExclusionApplicable(aemConfiguration)
				&& checkForAssetPathInclusionExclusion(assetPath, aemConfiguration)) {
			return Boolean.FALSE;
		}
		return Boolean.TRUE;
	}

	/**
	 * Method to build page ItemInfo.
	 *
	 * @param aemPageData aem page data object
	 * @return itemInfo
	 */
	public ItemInfo buildPageItemInfo(AemPageData aemPageData) throws JSONException {
		Map<String, String> metadata = new HashMap<>(aemPageData.getMetadata());
		if (!Objects.nonNull(aemPageData.getPageDataInputStream())) {
			pageItemIdInputStreamMap.put(aemPageData.getPagePath(),
					new ByteArrayInputStream(aemPageData.getMetadata().get(JCR_TITLE)
							.getBytes(StandardCharsets.UTF_8)));
		} else {
			pageItemIdInputStreamMap.put(aemPageData.getPagePath(),
					aemPageData.getPageDataInputStream());
		}
		metadata.put(ITEM_PRINCIPAL, getAllowedAndDeniedBy(aemPageData.getAemAclData()));
		return (createItemInfo(aemPageData.getPagePath(),
				metadata, ItemState.ADDED.toString()));
	}

	/**
	 * Method to build asset ItemInfo.
	 *
	 * @param aemAssetData aem asset data object
	 * @return itemInfo
	 */
	public ItemInfo buildAssetItemInfo(AemAssetData aemAssetData) throws JSONException {
		Map<String, String> metadata = new HashMap<>(aemAssetData.getAssetMetadata());
		assetItemIdInputStreamMap.put(aemAssetData.getAssetPath(),
				aemAssetData.getAssetInputStream());
		metadata.put(ITEM_PRINCIPAL, getAllowedAndDeniedBy(aemAssetData.getAemAclData()));
		return (createItemInfo(aemAssetData.getAssetPath(),
				metadata, ItemState.ADDED.toString()));
	}

	/**
	 * Method to create ItemInfo.
	 *
	 * @param metadata  Item meta data
	 * @param itemState Item state
	 * @return itemInfo
	 */
	private ItemInfo createItemInfo(String key, Map<String, String> metadata, String itemState) {
		long eventTime = Date.from(Instant.now()).getTime();
		return ItemInfo.builder().eventTime(eventTime).itemId(key).itemType(ItemType.DOCUMENT)
				.itemState(ItemState.valueOf(itemState)).metadata(metadata).build();
	}

	/**
	 * Method to check inclusion/exclusion filters based on {@link AemConfiguration}.
	 *
	 * @param aemConfiguration the configuration
	 * @return boolean
	 */
	public boolean isPageInclusionExclusionApplicable(AemConfiguration aemConfiguration) {
		List<String> inclusion = aemConfiguration.getPagePathInclusionPatterns();
		List<String> exclusion = aemConfiguration.getPagePathExclusionPatterns();
		return !CollectionUtils.isNullOrEmpty(exclusion) || !CollectionUtils.isNullOrEmpty(inclusion);
	}

	/**
	 * Method to check inclusion/exclusion filters based on {@link AemConfiguration}.
	 *
	 * @param aemConfiguration the configuration
	 * @return boolean boolean
	 */
	public boolean isAssetPathInclusionExclusionApplicable(AemConfiguration aemConfiguration) {
		List<String> inclusion = aemConfiguration.getAssetPathInclusionPatterns();
		List<String> exclusion = aemConfiguration.getAssetPathExclusionPatterns();
		return !CollectionUtils.isNullOrEmpty(exclusion) || !CollectionUtils.isNullOrEmpty(inclusion);
	}

	/**
	 * Method to check if the page should be crawled based on the {@link AemConfiguration}.
	 *
	 * @param pagePath         input parameter
	 * @param aemConfiguration input parameter
	 * @return shouldCrawl boolean
	 */
	public boolean checkForPagePathInclusionExclusion(String pagePath,
			AemConfiguration aemConfiguration) {
		List<String> inclusion = new ArrayList<>(aemConfiguration.getPagePathInclusionPatterns());
		List<String> exclusion = new ArrayList<>(aemConfiguration.getPagePathExclusionPatterns());
		boolean shouldCrawl = Boolean.FALSE;

		List<String> inclusionPatterns = getValidPatterns(inclusion, pagePath);
		if (!CollectionUtils.isNullOrEmpty(inclusion)
				&& !CollectionUtils.isNullOrEmpty(inclusionPatterns)) {
			shouldCrawl = Boolean.TRUE;
		}
		if (!shouldCrawl && CollectionUtils.isNullOrEmpty(inclusion)) {
			shouldCrawl = Boolean.TRUE;
		}
		List<String> exclusionPatterns = getValidPatterns(exclusion, pagePath);
		if (!CollectionUtils.isNullOrEmpty(exclusion)
				&& !CollectionUtils.isNullOrEmpty(exclusionPatterns)) {
			shouldCrawl = Boolean.FALSE;
		}
		return !shouldCrawl;
	}

	/**
	 * Method to check if the asset should be crawled based on the {@link AemConfiguration}.
	 *
	 * @param assetPath         input parameter
	 * @param aemConfiguration input parameter
	 * @return shouldCrawl boolean
	 */
	public boolean checkForAssetPathInclusionExclusion(String assetPath,
			AemConfiguration aemConfiguration) {
		List<String> inclusion = new ArrayList<>(aemConfiguration.getAssetPathInclusionPatterns());
		List<String> exclusion = new ArrayList<>(aemConfiguration.getAssetPathExclusionPatterns());
		boolean shouldCrawl = Boolean.FALSE;

		List<String> inclusionPatterns = getValidPatterns(inclusion, assetPath);
		if (!CollectionUtils.isNullOrEmpty(inclusion)
				&& !CollectionUtils.isNullOrEmpty(inclusionPatterns)) {
			shouldCrawl = Boolean.TRUE;
		}
		if (!shouldCrawl && CollectionUtils.isNullOrEmpty(inclusion)) {
			shouldCrawl = Boolean.TRUE;
		}
		List<String> exclusionPatterns = getValidPatterns(exclusion, assetPath);
		if (!CollectionUtils.isNullOrEmpty(exclusion)
				&& !CollectionUtils.isNullOrEmpty(exclusionPatterns)) {
			shouldCrawl = Boolean.FALSE;
		}
		return !shouldCrawl;
	}

	/**
	 * Method to get valid patterns for inclusion/exclusion filter.
	 *
	 * @param patterns input parameter.
	 * @param text     input parameter.
	 * @return List valid patterns
	 */
	public List<String> getValidPatterns(final List<String> patterns, final String text) {
		List<String> finalPatterns = new ArrayList();
		if (patterns != null) {
			patterns.forEach(p -> {
				try {
					Pattern regex = Pattern.compile(p);
					Matcher matcher = regex.matcher(text);
					if (matcher.find()) {
						finalPatterns.add(p);
					}
				} catch (Exception e) {
					throw new ContinuableBadRequestException(e.getMessage());
				}
			});
		}
		return finalPatterns;
	}

	private String getAllowedAndDeniedBy(AemAclData aemAclData) {
		AemCollaborationInfo aemCollaborationInfo = new AemCollaborationInfo();
		aemAclData.getEffectiveAcl().forEach(principal -> {
			try {
				if (isUser(principal)) {
					aemCollaborationInfo.addAllowUser(principal);
				} else {
					aemCollaborationInfo.addAllowGroup(principal);
				}
			} catch (URISyntaxException | IOException e) {
				throw new RuntimeException(e);
			}
		});
		aemAclData.getDenyPrincipal().forEach(principal -> {
			try {
				if (isUser(principal)) {
					aemCollaborationInfo.addDenyUser(principal);
				} else {
					aemCollaborationInfo.addDenyGroup(principal);
				}
			} catch (URISyntaxException | IOException e) {
				throw new RuntimeException(e);
			}
		});
		return new Gson().toJson(aemCollaborationInfo);
	}
}