package com.patternhelloworld.securityhelper.oauth2.client.domain.customer.dao;

import com.patternhelloworld.securityhelper.oauth2.client.domain.customer.entity.CustomerRole;
import org.springframework.data.jpa.repository.JpaRepository;


public interface CustomerRoleRepository extends JpaRepository<CustomerRole, Long> {

}
