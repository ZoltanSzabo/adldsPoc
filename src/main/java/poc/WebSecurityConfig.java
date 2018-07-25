package poc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${spring.ldap.url}")
	private String url;
	@Value("${spring.ldap.rootDN}")
	private String rootDn;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				.anyRequest()
				.fullyAuthenticated()
				.and()
				.formLogin();
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		CustomAuthenticationProvider adProvider =
				new CustomAuthenticationProvider(null, url, rootDn);
//		ActiveDirectoryLdapAuthenticationProvider adProvider =
//				new ActiveDirectoryLdapAuthenticationProvider(null, url, rootDn);
		adProvider.setConvertSubErrorCodesToExceptions(true);
		adProvider.setUseAuthenticationRequestCredentials(true);
		auth.authenticationProvider(adProvider);
		auth.eraseCredentials(false);
	}

}
