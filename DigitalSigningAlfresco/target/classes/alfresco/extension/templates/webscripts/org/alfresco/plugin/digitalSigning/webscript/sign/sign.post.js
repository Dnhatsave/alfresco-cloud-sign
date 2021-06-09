try {
	var jsonObject = jsonUtils.toObject(requestbody.content);

	var document = jsonObject.document;
	var destination = jsonObject.pathNodeRef;
	var keyPassword = jsonObject.password;
	
	var parameters = new Object();
	parameters.keyPassword=keyPassword;
	parameters.document=document;
	parameters.destination=destination;
	
	digitalSigning.sign(parameters);
	model.result = "success";
} catch (e) {
	model.result = "error";
	model.error = (e.javaException == null ? e.rhinoException.message : e.javaException.message);
}