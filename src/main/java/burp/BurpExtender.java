/*
Copyright 2016 LinkedIn Corp. Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.
 */

package burp;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;



public class BurpExtender implements IBurpExtender, IScannerCheck {

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;
  private Set<String> exploitParams = new HashSet<String>();
  Deque<String> lastParamValues;
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    exploitParams.add("callback");
    exploitParams.add("target");
    exploitParams.add("cb");
    exploitParams.add("jsonp");
    exploitParams.add("cmd");
    exploitParams.add("readyFunction");
    exploitParams.add("jsoncallback");

    lastParamValues = new LinkedList<String>();
    this.callbacks = callbacks;
    helpers = callbacks.getHelpers();
    callbacks.setExtensionName("SOMEtime");
    callbacks.registerScannerCheck(this);
  }

  public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
    boolean isSwf = false;
    List<IScanIssue> issues = new ArrayList<IScanIssue>(1);
    String responseBody = getStringResponseBody(baseRequestResponse);
    if( responseBody == null ) {
        return null;
    }

    byte[] urlDecode = helpers.urlDecode(baseRequestResponse.getRequest());

    // make sure to get correct parameters
    List<IParameter> params = helpers.analyzeRequest(urlDecode).getParameters();

    if( helpers.analyzeRequest(baseRequestResponse).getUrl().toString().contains(".swf") ) {
      isSwf = true;
    }


    Document doc = Jsoup.parse(responseBody);
    Elements scriptTags = doc.getElementsByTag("script");

    // check if something in params is equal to something in exploitParams
    //  find which one matched
    for( IParameter p : params ) {
      if( p.getValue().isEmpty() ) {
        continue;
      }

      // SWF files that contain a callback are usually vulnerable
      if( exploitParams.contains(p.getName()) && isSwf ) {
        String detail = "Same Origin Method Execution might be possible. This is rated as high severity because it appears the callback parameter <b>"
              + p.getName() + "</b> is specifying which method to call in the response, and points to a .SWF file.";
        issues.add( new SOMEIssue(baseRequestResponse, "High", "Firm", detail) );
        return issues;
      }

      for( Element tag : scriptTags ) {
        // check that we are inserting our parameter directly into a src tag
        String src = tag.attr("src");
        for( String sink : exploitParams ) {
          String matcher = sink + "=" + p.getValue();

          if( src.contains(matcher) ) {
            String detail = "Same Origin Method Execution might be possible. This is rated as high severity because it appears the callback parameter"
                + " is specifying which method to call in a javascript context. Search for <b>" + sink + "=" + p.getValue() + "</b> in the response to determine validity.";
            issues.add( new SOMEIssue(baseRequestResponse, "High", "Certain", detail) );
            return issues;
          }
        }
        // get code between the script tags
        String jsCode = tag.html();
        // check that we are executing javascript with our parameter value as a method name
        //  this would find things like <script>opener.{callback}({jsonp}) or <script>{callback}( {jsonp} )</script>
        if( jsCode.contains(p.getValue() + "({") && Character.toString(jsCode.charAt((jsCode.indexOf(p.getValue()+"({"))-1)).matches("[^a-zA-Z0-9]") ) {
          String detail = "Same Origin Method Execution might be possible. This is rated as high severity because it appears the callback parameter"
              + " is specifying which method to directly call in the response under a Javascript context."
              + " Search for <b>" + p.getValue() + "({</b> in the response to determine validity.";
          issues.add( new SOMEIssue(baseRequestResponse, "High", "Certain", detail) );
          return issues;
        }
      }

      // checks for JSONP endpoint problems, find SOME by using the JSONP endpoint
      //   look for value({
      String escapedParam = Pattern.quote(p.getValue());
      Pattern pattern = Pattern.compile(escapedParam+"\\(\\{");
      Matcher m = pattern.matcher(responseBody);
      if( m.find() ) {
        // check that this parameter value has been passed previously
        if( lastParamValues.contains(p.getValue()) ) {
          // jQuery auto generated JSONP requests are not vulnerable
          if( responseBody.startsWith("jQuery") ) {
            continue;
          }

          // capture what appears to be the method name
          //   and check that it is actually a value that is stored
          Pattern pattern2 = Pattern.compile("\\.?(\\w*" + escapedParam + ")\\(\\{");
          Matcher m2 = pattern2.matcher(responseBody);
          while( m2.find() ) {
            if( lastParamValues.contains(m2.group(1)) ) {
              String detail = "Same Origin Method Execution might be possible. This is rated as high severity because it appears the callback parameter"
                  + " is specifying which method to directly call in the response. It appears"
                  + " that the callback value has been passed by previous request parameters. Search for " + p.getValue()
                  + " in the previous request parameters. To determine if it is a false positive search for <b>" + p.getValue() + "({"
                      + "</b> and manually verify in the response.";
              issues.add( new SOMEIssue(baseRequestResponse, "High", "Certain", detail) );
              return issues;
            }
          }
        }
      }
    }

    for( IParameter p : params ) {
      if( p.getType() != IParameter.PARAM_COOKIE ) {
        if( lastParamValues.size() > 50 ) {
          lastParamValues.pop();
        }
        lastParamValues.push(p.getValue());
      }
    }
    return null;
  }

  private String getStringResponseBody(IHttpRequestResponse baseRequestResponse) {
    String response = null;
    try {
      response = new String(baseRequestResponse.getResponse(), "UTF-8");
      response = response.substring(helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset());
    } catch (UnsupportedEncodingException e) {
      System.out.println("Error converting string");
    }
    return response;
  }

  public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
    if( existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()) ) {
      return -1;
    }
    else {
      return 0;
    }
  }

  class SOMEIssue implements IScanIssue {

    private IHttpRequestResponse reqres;
    private String severity;
    private String confidence;
    private String detail;

    public SOMEIssue(IHttpRequestResponse reqres, String severity, String confidence, String detail ) {
        this.reqres = reqres;
        this.severity = severity;
        this.confidence = confidence;
        this.detail = detail;
    }

    public String getIssueName() {
        return "SOME (Same Origin Method Execution)";
    }

    public int getIssueType() {
        return 0x08000000; //See http://portswigger.net/burp/help/scanner_issuetypes.html
    }

    public String getSeverity() {
        return severity;
    }

    public String getConfidence() {
        return confidence;
    }

    public String getIssueBackground() {
        return "Same Origin Method Execution occurs when a parameter is being used to define a function to execute"
            + " in a Javascript context. Normally, this occurs with JSONP and Flash endpoints as they contain a "
            + "'callback' parameter.";
    }

    public String getRemediationBackground() {
        return "<b>If a user-defined callback is necessary for the application to work:<ul>" + 
            "<li>User's function names should not be executed as Javascript unless they match a whitelist</li>" +
           "<li>Alternatively, use postMessage for cross-domain functionality</li></ul>";
    }

    public String getIssueDetail() {
      return detail;
    }

    public String getRemediationDetail() {
        return null;
    }

    public IHttpRequestResponse[] getHttpMessages() {
      IHttpRequestResponse[] msgs = new IHttpRequestResponse[1];
      msgs[0] = reqres;
      return msgs;
    }
    public URL getUrl() {
      return helpers.analyzeRequest(reqres).getUrl();
    }

    public IHttpService getHttpService() {
      return reqres.getHttpService();
    }
}

  public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
    return null;
  }
}
