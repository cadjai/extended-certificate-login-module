package org.jboss.as.security.auth;

import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.security.PicketBoxLogger;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.BaseCertLoginModule;
import org.jboss.security.mapping.providers.MappingProviderUtil;

/**
 * 
 */

/**
 * @author cadjai
 * 
 */
public class ExtendedCertificateLoginModule extends BaseCertLoginModule {

	// private static final SecurityLogger LOGGER = SecurityLogger.ROOT_LOGGER;

	private static final String DEFAULT_ROLE_OPTION = "defaultRoles";
	private static final String ROLES = "roles";
	private static final String ROLES_DEPTH = "rolesDepth";
	private static final String CN_PREFIX = "CN=";
	private static final String CN_SEPARATOR = ",";

	private static final String[] ALL_OPTIONS = new String[] {
			DEFAULT_ROLE_OPTION, ROLES, ROLES_DEPTH };

	private String defaultRoles = "admin,SuperUser";
	private String[] tokens = null;
	private String roles;
	private int depth = 0;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		addValidOptions(ALL_OPTIONS);
		super.initialize(subject, callbackHandler, sharedState, options);

		try {
			if (options != null) {
				if (options.containsKey(DEFAULT_ROLE_OPTION)) {
					String defaultroles = (String) options
							.get(DEFAULT_ROLE_OPTION);
					if (null != defaultroles && !defaultroles.isEmpty()) {
						defaultRoles = defaultroles;
					}
				}
				if (options.containsKey(ROLES)) {
					roles = (String) options.get(ROLES);
					if (null != roles && !roles.isEmpty()) {
						this.tokens = MappingProviderUtil
								.getRolesFromCommaSeparatedString(roles);
					} else {
						this.tokens = MappingProviderUtil
								.getRolesFromCommaSeparatedString(defaultRoles);
					}
				}
				if (options.containsKey(ROLES_DEPTH)) {
					this.depth = Integer.parseInt((String) options
							.get(ROLES_DEPTH));
				}
			}

		} catch (Exception e) {
			PicketBoxLogger.LOGGER.error("Error parsing passed in roles ["
					+ DEFAULT_ROLE_OPTION + ": " + defaultRoles + "] [ "
					+ ROLES + ": " + roles + "]", e);
		}

	}

	@Override
	protected Group[] getRoleSets() throws LoginException {
		String targetUser = getUsername();
		String username = targetUser;
		int idxCN = username.indexOf(CN_PREFIX);

		if (idxCN > -1) {
			int idxSep = username.indexOf(CN_SEPARATOR, idxCN);
			if (idxSep > -1) {
				username = username.substring(idxCN + 3, idxSep);
			} else {
				username = username.substring(idxCN + 3);
			}

		}
		// HashMap<String, Group> setsMap = new HashMap<String, Group>();
		SimpleGroup rolesGroup = new SimpleGroup("Roles");
		ArrayList<Group> groups = new ArrayList<Group>();
		groups.add(rolesGroup);
		String usrKey = "";
		if (this.depth <= 1) {
			usrKey = username.substring(0, 3);
			addRolesForToekn(rolesGroup, usrKey);
		} else {
			for (int j = 1; j <= this.depth; j++) {
				usrKey = username.substring((j - 1) * 4, 4 * j);
				if (!usrKey.isEmpty() && usrKey.length() == 4) {
					addRolesForToekn(rolesGroup, usrKey);
				}
			}
		}

		Group[] roleSets = new Group[groups.size()];
		groups.toArray(roleSets);
		return roleSets;
	}

	/**
	 * @param rolesGroup
	 * @param usrKey
	 */
	private void addRolesForToekn(SimpleGroup rolesGroup, String usrKey) {
		for (int i = 0; i < this.tokens.length; i++) {
			if (this.tokens[i].contains(usrKey)) {
				Principal p = null;
				try {
					p = this.createIdentity(this.tokens[i]);
				} catch (Exception e) {
					PicketBoxLogger.LOGGER.error(
							"Error creating an identity for the following token [ "
									+ this.tokens[i] + " ] ", e);
				}
				if (null != p) {
					rolesGroup.addMember(p);
				}
			}
		}
	}

}
