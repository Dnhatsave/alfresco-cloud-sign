<#assign el=args.htmlid?html>
<div id="${el}-dialog" class="depot-casier">
   <div id="${el}-dialogTitle" class="hd"><#if displayName??>${msg("title", displayName)}<#else>${msg("title.multiple")}</#if></div>
   <div class="bd">
     <form id="${el}-form" action="" method="post">
	 	<input type="hidden" name="document" id="${el}-document" value="${nodeRef}" />
	 	<input type="hidden" name="pathNodeRef" id="${el}-pathNodeRef" />
		<div class="yui-gd">
            <div class="yui-u first"><label for="${el}-destination">${msg("label.destination")}:</label></div>
            <div class="yui-u">
               <button type="button" name="-" id="${el}-selectFilterPath-button">${msg("label.browse")}</button>&nbsp;<img src="${url.context}/res/components/documentlibrary/images/sign-help.png" onclick="javascript:help();" /> 
               <div id="${el}-sign-path-help" style="display : none;"><#if displayName??>${msg("label.destination.information")}<#else>${msg("label.destination.information.multiple")}</#if></div>
               <br /><span id="${el}-filterPathView"></span>
            </div>
         </div>
         <div class="yui-gd">
            <div class="yui-u first"><label for="${el}-password">${msg("label.password")}:</label></div>
            <div class="yui-u"><input id="${el}-password" type="password" name="password" value="" /> * </div>
         </div>     
	 	 <div class="bdft">
	    	<input type="submit" id="${el}-ok" value="${msg("button.ok")}" tabindex="0" />
	    	<input type="button" id="${el}-cancel" value="${msg("button.cancel")}" tabindex="0" />
	 	 </div>
     </form>
   </div>
</div>
<script type="text/javascript">//<![CDATA[
    
    
    function help() {
    	if (document.getElementById("${el}-sign-path-help").style.display == "none") {
			document.getElementById("${el}-sign-path-help").style.display = "block";
		} else {
			document.getElementById("${el}-sign-path-help").style.display = "none";
		}
    }
    //]]>
</script>
