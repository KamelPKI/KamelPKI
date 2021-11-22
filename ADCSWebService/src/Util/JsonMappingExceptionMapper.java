package Util;

import javax.json.stream.JsonParsingException;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
public class JsonMappingExceptionMapper implements ExceptionMapper<JsonParsingException> {
	private static final Logger logger = LoggerFactory.getLogger(JsonMappingExceptionMapper.class);

	@Override
	public Response toResponse(JsonParsingException exception) {
		JSONObject response = new JSONObject();
		try {
			response.put("status", "error");
			response.put("response", "Invalid JSON request object: " + exception.getMessage());
			response.put("error", "Unable to parse JSON request");
		} catch (JSONException e) {
			logger.error("error building JSON object", e);
		}
		
		return Response.status(Response.Status.BAD_REQUEST).entity(response.toString()).build();
	}

}
