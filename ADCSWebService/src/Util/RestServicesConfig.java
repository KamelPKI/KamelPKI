package Util;

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig;


//This class shows the main package "ADCS.RestAPI" which contain AdcsService class
@ApplicationPath("")
public class RestServicesConfig extends ResourceConfig {
	public RestServicesConfig() {
		packages("com.fasterxml.jackson.jaxrs.json");
		packages("ADCS.RestAPI");
		register(new JsonMappingExceptionMapper());
	}
	
	
}
