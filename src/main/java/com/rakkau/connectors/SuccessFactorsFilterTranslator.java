package com.rakkau.connectors;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;

public class SuccessFactorsFilterTranslator  extends AbstractFilterTranslator<SuccessFactorsFilter> {

	private static final Log logger = Log.getLog(SuccessFactorsFilterTranslator.class);

	@Override
	protected SuccessFactorsFilter createContainsExpression(ContainsFilter filter, boolean not) {
		logger.info("createContainsExpression, filter: {0}, not: {1}", filter, not);
		SuccessFactorsFilter userFilter = new SuccessFactorsFilter();
		Attribute attr = filter.getAttribute();
		logger.info("attr.getName:  {0}, attr.getValue: {1}, Uid.NAME: {2}, Name.NAME: {3}", attr.getName(), attr.getValue(), Uid.NAME, Name.NAME);

		if (Uid.NAME.equals(attr.getName())) {
			if (attr.getValue() != null && attr.getValue().get(0) != null) {
				userFilter.byUid = String.valueOf(attr.getValue().get(0));
			}
		}
		if (Name.NAME.equals(attr.getName())) {
			if (attr.getValue() != null && attr.getValue().get(0) != null) {
				userFilter.byName = String.valueOf(attr.getValue().get(0));
			}
		}
		return userFilter;
	}

	@Override
	protected SuccessFactorsFilter createEqualsExpression(EqualsFilter filter, boolean not) {

		logger.info("createEqualsExpression, filter: {0}, not: {1}", filter, not);

		if (not) {
			return null;
		}

		SuccessFactorsFilter userFilter = new SuccessFactorsFilter();
		Attribute attr = filter.getAttribute();
		logger.info("attr.getName:  {0}, attr.getValue: {1}, Uid.NAME: {2}, Name.NAME: {3}", attr.getName(), attr.getValue(), Uid.NAME, Name.NAME);

		if (Uid.NAME.equals(attr.getName())) {
			if (attr.getValue() != null && attr.getValue().get(0) != null) {
				userFilter.byUid = String.valueOf(attr.getValue().get(0));
			}
		}
		if (Name.NAME.equals(attr.getName())) {
			if (attr.getValue() != null && attr.getValue().get(0) != null) {
				userFilter.byName = String.valueOf(attr.getValue().get(0));
			}
		}
		return userFilter;
	}
}
