package com.kineticdata.bridgehub.adapter.chef;

import com.google.gson.Gson;
import com.kineticdata.bridgehub.adapter.BridgeAdapter;
import com.kineticdata.bridgehub.adapter.BridgeError;
import com.kineticdata.bridgehub.adapter.BridgeRequest;
import com.kineticdata.bridgehub.adapter.BridgeUtils;
import com.kineticdata.bridgehub.adapter.Count;
import com.kineticdata.bridgehub.adapter.Record;
import com.kineticdata.bridgehub.adapter.RecordList;
import static com.kineticdata.bridgehub.adapter.chef.ChefAdapter.logger;
import com.kineticdata.commons.v1.config.ConfigurableProperty;
import com.kineticdata.commons.v1.config.ConfigurablePropertyMap;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.CompareToBuilder;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.slf4j.LoggerFactory;


public class ChefAdapter implements BridgeAdapter {
    /*----------------------------------------------------------------------------------------------
     * PROPERTIES
     *--------------------------------------------------------------------------------------------*/

    /** Defines the adapter display name */
    public static final String NAME = "Chef Bridge";

    /** Defines the logger */
    protected static final org.slf4j.Logger logger = LoggerFactory.getLogger(ChefAdapter.class);

    /** Adapter version constant. */
    public static String VERSION;
    /** Load the properties version from the version.properties file. */
    static {
        try {
            java.util.Properties properties = new java.util.Properties();
            properties.load(ChefAdapter.class.getResourceAsStream("/"+ChefAdapter.class.getName()+".version"));
            VERSION = properties.getProperty("version");
        } catch (IOException e) {
            logger.warn("Unable to load "+ChefAdapter.class.getName()+" version properties.", e);
            VERSION = "Unknown";
        }
    }

    /** Defines the collection of property names for the adapter */
    public static class Properties {
        public static final String PROPERTY_USERNAME = "Username";
        public static final String PROPERTY_PEM_INPUT_TYPE = "Pem Input Type";
        public static final String PROPERTY_PEM_CONTENT = "Pem Content";
        public static final String PROPERTY_PEM_LOCATION = "Pem Location";
        public static final String PROPERTY_API_ENDPOINT = "API Endpoint";
    }

    public static class PemTypes {
        public static final String FILE_SYSTEM = "On File System";
        public static final String FILE_CONTENT = "File Content";
    }

    private final ConfigurablePropertyMap properties = new ConfigurablePropertyMap(
        new ConfigurableProperty(Properties.PROPERTY_USERNAME).setIsRequired(true),
        new ConfigurableProperty(Properties.PROPERTY_PEM_INPUT_TYPE).setIsRequired(true)
            .addPossibleValues(PemTypes.FILE_SYSTEM,PemTypes.FILE_CONTENT).setValue(PemTypes.FILE_SYSTEM),
        new ConfigurableProperty(Properties.PROPERTY_PEM_LOCATION).setIsRequired(true)
            .setDependency(Properties.PROPERTY_PEM_INPUT_TYPE, PemTypes.FILE_SYSTEM)
            .setDescription("A file system path pointing to a copy of the configured username's .pem file."),
        new ConfigurableProperty(Properties.PROPERTY_PEM_CONTENT).setIsRequired(true).setIsSensitive(true)
            .setDependency(Properties.PROPERTY_PEM_INPUT_TYPE,PemTypes.FILE_CONTENT)
            .setDescription("The full contents of the configured username's .pem file."),
        new ConfigurableProperty(Properties.PROPERTY_API_ENDPOINT).setIsRequired(true)
            .setValue("https://api.opscode.com/organizations/YOUR_ORGANIZATION")
            .setDescription("Can be found in the URL (the whole URL up until the organization name) when viewing Chef in the browser.")
    );

    private String username;
    private PrivateKey privateKey;
    private String apiEndpoint;
    protected static PoolingHttpClientConnectionManager poolingConnManager = new PoolingHttpClientConnectionManager();

    /**
     * Structures that are valid to use in the bridge
     */
    public static final List<String> VALID_STRUCTURES = Arrays.asList(new String[] {
        "Cookbooks","Nodes","Recipes"
    });

    /*---------------------------------------------------------------------------------------------
     * SETUP METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public void initialize() throws BridgeError {
        this.username = properties.getValue(Properties.PROPERTY_USERNAME);
        String pemContent = properties.getValue(Properties.PROPERTY_PEM_CONTENT);
        pemContent = pemContent.replace("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\r\n");
        pemContent = pemContent.replace("-----END RSA PRIVATE KEY-----", "\r\n-----END RSA PRIVATE KEY-----");
        try {
            Reader reader;
            if (properties.getValue(Properties.PROPERTY_PEM_INPUT_TYPE).equals(PemTypes.FILE_SYSTEM)) {
                reader = new FileReader(properties.getValue(Properties.PROPERTY_PEM_LOCATION));
            } else if (properties.getValue(Properties.PROPERTY_PEM_INPUT_TYPE).equals(PemTypes.FILE_CONTENT)) {
                reader = new StringReader(pemContent);
            } else {
                throw new BridgeError("Invalid Pem Type Selected: "+properties.getValue(Properties.PROPERTY_PEM_INPUT_TYPE));
            }
            PEMParser pemParser = new PEMParser(reader);
            Object object = pemParser.readObject();

            PKCS8EncodedKeySpec keySpec;
            if (object instanceof PEMKeyPair) {
                PrivateKeyInfo info = ((PEMKeyPair)object).getPrivateKeyInfo();
                keySpec = new PKCS8EncodedKeySpec(info.getEncoded());
            } else if (object instanceof PrivateKeyInfo) {
                PrivateKeyInfo info = (PrivateKeyInfo)object;
                keySpec = new PKCS8EncodedKeySpec(info.getEncoded());
            } else {
                throw new BridgeError("PEM file type '"+object.getClass().toString()+"' not recognized");
            }

            KeyFactory factory = KeyFactory.getInstance("RSA");
            this.privateKey = factory.generatePrivate(keySpec);
        } catch (FileNotFoundException e) {
            throw new BridgeError("Error loading PEM file.",e);
        } catch (IOException e) {
            throw new BridgeError("Error loading PEM file.",e);
        } catch (NoSuchAlgorithmException e) {
            throw new BridgeError(e);
        } catch (InvalidKeySpecException e) {
            throw new BridgeError(e);
        }
        this.apiEndpoint = properties.getValue(Properties.PROPERTY_API_ENDPOINT).replaceFirst("/$","");
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getVersion() {
        return VERSION;
    }

    @Override
    public void setProperties(Map<String,String> parameters) {
        properties.setValues(parameters);
    }

    @Override
    public ConfigurablePropertyMap getProperties() {
        return properties;
    }

    /*---------------------------------------------------------------------------------------------
     * IMPLEMENTATION METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public Count count(BridgeRequest request) throws BridgeError {
        RecordList recordList = search(request);
        List<Record> records = recordList.getRecords();

        return new Count(records.size());
    }

    @Override
    public Record retrieve(BridgeRequest request) throws BridgeError {
        RecordList recordList = search(request);
        List<Record> records = recordList.getRecords();

        Record record;
        if (records.size() > 1) {
            throw new BridgeError("Multiple results matched an expected single match query");
        } else if (records.isEmpty()) {
            record = new Record(null);
        } else {
            record = new Record(records.get(0).getRecord(),request.getFields());
        }

        // Returning the response
        return record;
    }

    @Override
    public RecordList search(BridgeRequest request) throws BridgeError {
        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }

        // Initialize variables
        List<Record> records = new ArrayList<Record>();
        HttpResponse response;
        String output = "";

        ChefQualificationParser parser = new ChefQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());

        // For each structure the same general flow is followed
        //   Prepare the API Call :: Make the API Call :: Parse the response to JSON ::
        //   Build Record List :: Make threaded calls for additional details (if necessary)
        if ("Cookbooks".equals(request.getStructure())) {
            List<String> cookbookNames = null;

            // Prepare the API call
            String numVersions = "all";
            if (query.contains("nodeName=")) {
                Matcher m = Pattern.compile("nodeName=(.*?)(?:&|\\z)").matcher(query);
                if (m.find()) {
                    cookbookNames = getNodeRunListCookbookNames(m.group(1));
                }
                // Remove nodeName=.*? and any extra & from the query
                query = query.replaceFirst("nodeName=(.*?)(?:&|\\z)","");
                query = query.replaceFirst("&\\z","");
            }
            if (query.contains("version=_latest")) {
                // Set the num versions to 1 so it will only return the latest version
                numVersions = "1";
                // Remove version=_latest and any extra & from the query
                query = query.replaceFirst("(version=_latest&*|&*version=_latest)","");
            }

            // Make the API call
            response = request("GET",this.apiEndpoint+"/cookbooks?num_versions="+numVersions,"");

            try { output = EntityUtils.toString(response.getEntity()); }
            catch (IOException e) { throw new BridgeError("Error retrieving the entity from the HttpResponse object",e); }

            // Parse the Response to JSON
            JSONObject json = (JSONObject)JSONValue.parse(output);

            // Create Initial Record List
            for (String key : new ArrayList<String>(json.keySet())) {
                JSONObject cookbookDetails = (JSONObject)json.get(key);
                JSONArray versionDetails = (JSONArray)cookbookDetails.get("versions");
                for (Object vo : versionDetails) {
                    Map<String,Object> recordObj = new LinkedHashMap<String,Object>();
                    recordObj.put("name",key);
                    recordObj.put("version",(String)((JSONObject)vo).get("version"));
                    if (cookbookNames == null || cookbookNames.contains(key)) {
                        records.add(new Record(recordObj));
                    }
                }
            }

            // Filter records as much as possible before making threaded calls to get more cookbook
            // details (if those fields are being requested)
            if (extraDetailsNeeded(request)) {
                // Split the query into a name/version query and separate all other field queries so
                // that they can be used in separate filterRecords calls
                List<String> nameVersionQueries = new ArrayList<String>();
                List<String> otherQueries = new ArrayList<String>();
                for (String component : query.split("&")) {
                    if (component.matches("\\Aname=.*") || component.matches("\\Aversion=.*")) {
                        nameVersionQueries.add(component);
                    } else {
                        if (!component.isEmpty()) otherQueries.add(component);
                    }
                }
                String nameVersionQuery = StringUtils.join(nameVersionQueries,"&");
                query = StringUtils.join(otherQueries,"&");

                // Filter records for name/version
                records = filterRecords(records,nameVersionQuery);

                // Make the threaded calls to retrieve additional cookbook details
                // Initializing threading variables
                ExecutorService threadPool = Executors.newFixedThreadPool(5);
                Map<Record,Future<Map<String,Object>>> retrievedThreadsMap = new HashMap<Record,Future<Map<String,Object>>>();

                for (Record record : records) {
                    String name = (String)record.getValue("name");
                    String version = (String)record.getValue("version");
                    // Create threaded Future calls to be retrieve the JSONObject for each cookbook
                    // and corresponding version
                    Callable<Map<String,Object>> callable = new ChefApiRequestCallable("GET",this.apiEndpoint+"/cookbooks/"+name+"/"+version,"",this.username,this.privateKey);
                    Future<Map<String,Object>> future = threadPool.submit(callable);
                    retrievedThreadsMap.put(record,future);
                }

                for (Map.Entry<Record,Future<Map<String,Object>>> entry : retrievedThreadsMap.entrySet()) {
                    try {
                        Map<String,Object> cookbookDetails = entry.getValue().get();
                        // Remove the name and version from the returned cookbook details because the
                        // previously returned ones will be used for consistencies sake
                        cookbookDetails.remove("name");
                        cookbookDetails.remove("verion");
                        // Add the returned results to the associated Record
                        entry.getKey().getRecord().putAll(cookbookDetails);
                    } catch (InterruptedException e) {
                        throw new BridgeError("There was an error getting the threaded results for a specific Chef cookbook.",e);
                    } catch (ExecutionException e) {
                        throw new BridgeError("There was an error getting the threaded results for a specific Chef cookbook.",e);
                    }
                }
            }
        } else if ("Nodes".equals(request.getStructure())) {
            // Make the API call
            response = request("GET",this.apiEndpoint+"/nodes","");

            try { output = EntityUtils.toString(response.getEntity()); }
            catch (IOException e) { throw new BridgeError("Error retrieving the entity from the HttpResponse object",e); }

            // Parse the Response to JSON
            JSONObject json = (JSONObject)JSONValue.parse(output);
            // Create Initial Record List
            Set<String> jsonKeys = json.keySet();
            for (String key : jsonKeys) {
                Map<String,Object> recordObj = new LinkedHashMap<String,Object>();
                recordObj.put("name",key);
                recordObj.put("url",json.get(key));
                records.add(new Record(recordObj));
            }

            // Filter records as much as possible before making threaded calls to get more node
            // details (if those fields are being requested)
            if (extraDetailsNeeded(request)) {
                // Split the name querying out of the main query so it can be done before the threaded
                // calls need to be made to reduce the time before results are returned
                List<String> nameQueries = new ArrayList<String>();
                List<String> otherQueries = new ArrayList<String>();
                for (String component : query.split("&")) {
                    if (component.matches("\\Aname=.*")) {
                        nameQueries.add(component);
                    } else {
                        if (!component.isEmpty()) otherQueries.add(component);
                    }
                }
                String nameQuery = StringUtils.join(nameQueries,"&");
                query = StringUtils.join(otherQueries,"&");

                // Filter records based on name
                records = filterRecords(records, nameQuery);

                // Make the threaded calls to retrieve additional node details
                // Initializing threading variables
                ExecutorService threadPool = Executors.newFixedThreadPool(5);
                Map<Record,Future<Map<String,Object>>> retrievedThreadsMap = new HashMap<Record,Future<Map<String,Object>>>();

                for (Record record : records) {
                    String name = (String)record.getValue("name");
                    // Create threaded Future calls to be retrieve the JSONObject for each node
                    // and corresponding version
                    Callable<Map<String,Object>> callable = new ChefApiRequestCallable("GET",this.apiEndpoint+"/nodes/"+name,"",this.username,this.privateKey);
                    Future<Map<String,Object>> future = threadPool.submit(callable);
                    retrievedThreadsMap.put(record,future);
                }

                for (Map.Entry<Record,Future<Map<String,Object>>> entry : retrievedThreadsMap.entrySet()) {
                    try {
                        Map<String,Object> nodeDetails = entry.getValue().get();
                        // Add the returned results to the associated Record
                        entry.getKey().getRecord().putAll(nodeDetails);
                    } catch (InterruptedException e) {
                        throw new BridgeError("There was an error getting the threaded results for a specific Chef cookbook.",e);
                    } catch (ExecutionException e) {
                        throw new BridgeError("There was an error getting the threaded results for a specific Chef cookbook.",e);
                    }
                }
            }

        } else if ("Recipes".equals(request.getStructure())) {
            // Prepare the API request
            String name = null;
            String version = null;
            Matcher m = Pattern.compile("(cookbookName|cookbookVersion)=(.*?)(?:&|\\z)").matcher(query);
            while (m.find()) {
                if (m.group(1).toLowerCase().equals("cookbookname")) {
                    name = m.group(2);
                } else if (m.group(1).toLowerCase().equals("cookbookversion")) {
                    version = m.group(2);
                }
            }
            if (name == null || version == null) {
                throw new BridgeError("Invalid Query: 'cookbookName' and 'cookbookVersion' are both requried parameters.");
            }

            // Make the API Request
            response = request("GET",this.apiEndpoint+"/universe","");

            try { output = EntityUtils.toString(response.getEntity()); }
            catch (IOException e) { throw new BridgeError("Error retrieving the entity from the HttpResponse object",e); }

            // Parse the Response to JSON
            JSONObject json = (JSONObject)JSONValue.parse(output);
            // Create Initial Record List
            JSONObject cookbook = (JSONObject)json.get(name);
            if (cookbook == null) throw new BridgeError("A cookbook with the name '"+name+"' cannot be found.");
            JSONObject cookbookVersion = (JSONObject)cookbook.get(version);
            if (cookbookVersion == null) throw new BridgeError("A cookbook with the name'"+name+"' and version '"+version+"' cannot be found.");
            JSONObject dependencies = (JSONObject)cookbookVersion.get("dependencies");
            for (Object o : dependencies.entrySet()) {
                Map.Entry<String,Object> dependency = (Map.Entry<String,Object>)o;
                Map<String,Object> recordObj = new LinkedHashMap<String,Object>();
                recordObj.put("name",dependency.getKey());
                recordObj.put("versionRange",dependency.getValue());
                records.add(new Record(recordObj));
            }
        }

        // Each structure needs run the remaining steps to clean up its data before returning

        // Retrieve the fields from the request object. If they weren't included with the
        // request, attempt to retrieve them from the first Record object
        List<String> fields = request.getFields();
        if (fields == null || fields.isEmpty()) {
            fields = records.isEmpty() ? new ArrayList<String>() : records.get(0).getFieldNames();
        }

        // Filter, sort, and streamline the data set
        records = BridgeUtils.getNestedFields(fields,records);
        records = filterRecords(records,query);
        if (request.getMetadata("order") == null) {
            // name,type,desc assumes name ASC,type ASC,desc ASC
            Map<String,String> defaultOrder = new LinkedHashMap<String,String>();
            for (String field : fields) {
                // Don't sort version fields by default because they are strings and won't be
                // sorted in logical numberical order (1.9 would be sorted ahead of 1.49 even
                // though 1.49 is the higher version)
                if (!"version".equals(field)) defaultOrder.put(field, "ASC");
            }
            records = sortRecords(defaultOrder, records);
        } else {
            // Creates a map out of order metadata
            Map<String,String> orderParse = BridgeUtils.parseOrder(request.getMetadata("order"));
            records = sortRecords(orderParse, records);
        }

        // Building the output metadata
        Map<String,String> metadata = BridgeUtils.normalizePaginationMetadata(request.getMetadata());
        metadata.put("pageSize", "0");
        metadata.put("pageNumber", "1");
        metadata.put("offset", "0");
        metadata.put("size", String.valueOf(records.size()));
        metadata.put("count", metadata.get("size"));

        // Returning the response
        return new RecordList(fields, records, metadata);
    }

    /*----------------------------------------------------------------------------------------------
     * PRIVATE HELPER METHODS
     *--------------------------------------------------------------------------------------------*/

    private Boolean extraDetailsNeeded(BridgeRequest request) {
        boolean needDetails = false;
        if (request.getFields() == null || request.getFields().isEmpty()) {
            needDetails = true;
        } else if ("Cookbooks".equals(request.getStructure())) {
            needDetails = request.getFieldString().matches("\\A(name,?|version,?)*\\z") ? false : true;
            if (!needDetails && !request.getQuery().matches("\\A((name|version)=[^&]*?(&|\\z))*\\z")) needDetails = true;
        } else if ("Nodes".equals(request.getStructure())) {
            needDetails = request.getFields().size() == 1 && "name".equals(request.getFields().get(0).toLowerCase()) ? false : true;
            if (!needDetails && !request.getQuery().matches("\\Aname=[^&]*?\\z")) needDetails = true;
        } else if ("Recipes".equals(request.getStructure())) {

        }
        return needDetails;
    }

    private List<String> getNodeRunListCookbookNames(String nodeName) throws BridgeError {
        List<String> cookbookNames = new ArrayList<String>();

        BridgeRequest request = new BridgeRequest();
        request.setStructure("Nodes");
        request.setFields(Arrays.asList(new String[] { "run_list" }));
        request.setQuery("name="+nodeName);

        Record record;
        try {
            record = retrieve(request);
        } catch (BridgeError e) {
            throw new BridgeError("Error retrieving the run list for the node '"+nodeName+"' in an "
            +"attempt to retrieve cookbooks from the node.",e);
        }

        if (record.getRecord() != null) {
            List<String> runListNames = (ArrayList<String>)record.getValue("run_list");
            for (String name : runListNames) {
                // Substring from 7 to string.length-1 to delete recipe[ and ]
                String cookbookName = name.substring(7,name.length()-1);
                cookbookNames.add(cookbookName);
            }
        }

        return cookbookNames;
    }

    /**
     * This method builds and sends a request to the Chef REST API given the inputted data and returns an
     * HttpResponse object after the call has returned. This method mainly helps with creating a proper
     * signature for the request (documentation on the Chef REST API signing process can be found here -
     * https://docs.chef.io/api_chef_server.html), but it alos throws and logs an error if a 401 is retrieved on the
     * attempted call.
     *
     * @param url
     * @param headers
     * @return
     * @throws BridgeError
     */
    private HttpResponse request(String method, String url, String payload) throws BridgeError {
        Base64 base64 = new Base64(60,"\n".getBytes());

        // Build a datetime timestamp of the current time (in UTC).
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String datetime = df.format(new Date());

        // Create a URI from the request URL so that we can pull the host/path/port from it
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new BridgeError("There was an error parsing the inputted url '"+url+"' into a java URI.",e);
        }

        /* BUILD CANONCIAL REQUEST (uri, query, headers, signed headers, hashed payload)*/

        // Canonical URI (the part of the URL between the host and the ?. If blank, the uri is just /) and
        // remove any duplicate and trailing / characters
        String canonicalUri = uri.getPath().isEmpty() ? "/" : uri.getPath();
        canonicalUri = canonicalUri.replaceAll("/{2,}","/").replaceFirst("/$","");

        // Hashed payload (a SHA1 hash that is then Base64 encoded)
        String hashedPayload = new String(base64.encode(DigestUtils.sha1(payload))).trim();

        // Canonical Request (method, hashed uri path, hashed payload, utc timestamp, user id) signed
        // with the private key
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append("Method:").append(method).append("\n");
        requestBuilder.append("Hashed Path:").append(new String(base64.encode(DigestUtils.sha1(canonicalUri))).trim()).append("\n");
        requestBuilder.append("X-Ops-Content-Hash:").append(hashedPayload).append("\n");
        requestBuilder.append("X-Ops-Timestamp:").append(datetime).append("\n");
        requestBuilder.append("X-Ops-UserId:").append(this.username);

        logger.debug("Unsigned Canonical Request: \n"+requestBuilder.toString());
        // Sign the resulting string with the private key
        String hashedRequest;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
            byte[] cipherText = cipher.doFinal(requestBuilder.toString().getBytes());
            hashedRequest = new String(base64.encode(cipherText)).trim();
        } catch (Exception e) {
            throw new BridgeError(e);
        }

        /* CREATE THE HTTP REQUEST */
        HttpClient client = HttpClients.createDefault();
        HttpRequestBase request;
        try {
            if (method.toLowerCase().equals("get")) {
                request = new HttpGet(url);
            } else if (method.toLowerCase().equals("post")) {
                request = new HttpPost(url);
                ((HttpPost)request).setEntity(new StringEntity(payload));
            } else {
                throw new BridgeError("Http Method '"+method+"' is not supported");
            }
        } catch (UnsupportedEncodingException e) {
            throw new BridgeError(e);
        }

        /* ADD HEADERS TO HTTP REQUEST */
        request.setHeader("Accept","application/json");
        request.setHeader("Content-Type","application/json");
        String uriPort = uri.getPort() != -1 ? String.valueOf(uri.getPort()) : url.startsWith("https://") ? "443" : "80";
        request.setHeader("Host",uri.getHost()+":"+uriPort);
        request.setHeader("X-Chef-Version","11.4.0");
        request.setHeader("X-Ops-Sign","algorithm=sha1;version=1.0;");
        request.setHeader("X-Ops-Server-API-Version","1");
        request.setHeader("X-Ops-Timestamp",datetime);
        request.setHeader("X-Ops-UserId",this.username);
        request.setHeader("X-Ops-Content-Hash",hashedPayload);

        String[] authorizationChunks = hashedRequest.split("\\n");
        for (int i=0;i<authorizationChunks.length;i++) {
            request.setHeader("X-Ops-Authorization-"+String.valueOf(i+1),authorizationChunks[i].trim());
        }

        HttpResponse response;
        try {
            response = client.execute(request);

            if (response.getStatusLine().getStatusCode() == 401) { // || response.getStatusLine().getStatusCode() == 403) {
                logger.error(EntityUtils.toString(response.getEntity()));
                throw new BridgeError("User not authorized to access this resource. Check the logs for more details.");
            }
        } catch (IOException e) { throw new BridgeError(e); }

        return response;
    }

    private Pattern getPatternFromValue(String value) {
        // Escape regex characters from value
        String[] parts = value.split("(?<!\\\\)%");
        for (int i = 0; i<parts.length; i++) {
            if (!parts[i].isEmpty()) parts[i] = Pattern.quote(parts[i].replaceAll("\\\\%","%"));
        }
        String regex = StringUtils.join(parts,".*?");
        if (!value.isEmpty() && value.substring(value.length() - 1).equals("%")) regex += ".*?";
        return Pattern.compile("^"+regex+"$",Pattern.CASE_INSENSITIVE);
    }

    protected final List<Record> filterRecords(List<Record> records, String query) throws BridgeError {
        if (query == null || query.isEmpty()) return records;
        String[] queryParts = query.split("&");

        Map<String[],Object[]> queryMatchers = new HashMap<String[],Object[]>();
        // Iterate through the query parts and create all the possible matchers to check against
        // the user results
        for (String part : queryParts) {
            String[] split = part.split("=");
            String field = split[0].trim();
            String value = split.length > 1 ? split[1].trim() : "";

            Object[] matchers;
            // Find the field and appropriate values for the query matcher
            if (value.equals("true") || value.equals("false")) {
                matchers = new Object[] { getPatternFromValue(value), Boolean.valueOf(value) };
            } else if (value.equals("null")) {
                matchers = new Object[] { null, getPatternFromValue(value) };
            } else if (value.isEmpty()) {
                matchers = new Object[] { "" };
            } else {
                matchers = new Object[] { getPatternFromValue(value) };
            }
            queryMatchers.put(new String[] { field }, matchers);
        }

        // Start with a full list of records and then delete from the list when they don't match
        // a qualification. Will be left with a list of values that match all qualifications.
        List<Record> matchedRecords = records;
        for (Map.Entry<String[],Object[]> entry : queryMatchers.entrySet()) {
            List<Record> matchedRecordsEntry = new ArrayList<Record>();
            for (String field : entry.getKey()) {
                for (Record record : matchedRecords) {
                    // If the field being matched isn't a key on the record, add it to the matched
                    // record list automatically so we aren't trying to query against information
                    // that doesn't exist on the object
                    if (!record.getRecord().containsKey(field)) matchedRecordsEntry.add(record);
                    // Check if the object matches the field qualification if it hasn't already been
                    // successfully matched
                    if (!matchedRecordsEntry.contains(record)) {
                        // Get the value for the field
                        Object fieldValue = record.getValue(field);
                        // Check the possible value matchers against the field value
                        for (Object value : entry.getValue()) {
                            if (fieldValue == value || // Objects equal
                                fieldValue != null && value != null && (
                                    value.getClass() == Pattern.class && ((Pattern)value).matcher(fieldValue.toString()).matches() || // fieldValue != null && Pattern matches
                                    value.equals(fieldValue) // fieldValue != null && values equal
                                )
                            ) {
                                matchedRecordsEntry.add(record);
                                break;
                            }
                        }
                    }
                }
            }
            matchedRecords = matchedRecordsEntry;
        }

        return matchedRecords;
    }

    protected List<Record> sortRecords(final Map<String,String> fieldParser, List<Record> records) throws BridgeError {
        Collections.sort(records, new Comparator<Record>() {
            @Override
            public int compare(Record r1, Record r2){
                CompareToBuilder comparator = new CompareToBuilder();

                for (Map.Entry<String,String> entry : fieldParser.entrySet()) {
                    String field = entry.getKey();
                    String order = entry.getValue();

                    Object o1 = r1.getValue(field);
                    Object o2 = r2.getValue(field);
                    // If the object is a type that cannot be sorted, continue to the next field
                    if (o1 instanceof List || o1 instanceof Map) { continue; }
                    if (o2 instanceof List || o2 instanceof Map) { continue; }
                    // If the object is a string, lowercase the string so that capitalization doesn't factor into the comparison
                    if (o1 != null && o1.getClass() == String.class) {o1 = o1.toString().toLowerCase();}
                    if (o2 != null && o2.getClass() == String.class) {o2 = o2.toString().toLowerCase();}

                    if (order.equals("DESC")) {
                        comparator.append(o2,o1);
                    } else {
                        comparator.append(o1,o2);
                    }
                }

                return comparator.toComparison();
            }
        });
        return records;
    }
}

class ChefApiRequestCallable implements Callable<Map<String,Object>> {
    String method;
    String url;
    String payload;
    String username;
    PrivateKey privateKey;

    protected ChefApiRequestCallable(String method, String url, String payload, String username, PrivateKey privateKey) {
        this.method = method;
        this.url = url;
        this.payload = payload;
        this.username = username;
        this.privateKey = privateKey;
    }

    @Override
    public Map<String,Object> call() throws BridgeError {
        // Copying code from the private request() method from the main class with the only change
        // being to use a threading aware HttpClient
        Base64 base64 = new Base64(60,"\n".getBytes());

        // Build a datetime timestamp of the current time (in UTC).
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String datetime = df.format(new Date());

        // Create a URI from the request URL so that we can pull the host/path/port from it
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new BridgeError("There was an error parsing the inputted url '"+url+"' into a java URI.",e);
        }

        /* BUILD CANONCIAL REQUEST (uri, query, headers, signed headers, hashed payload)*/

        // Canonical URI (the part of the URL between the host and the ?. If blank, the uri is just /) and
        // remove any duplicate and trailing / characters
        String canonicalUri = uri.getPath().isEmpty() ? "/" : uri.getPath();
        canonicalUri = canonicalUri.replaceAll("/{2,}","/").replaceFirst("/$","");

        // Hashed payload (a SHA1 hash that is then Base64 encoded)
        String hashedPayload = new String(base64.encode(DigestUtils.sha1(payload))).trim();

        // Canonical Request (method, hashed uri path, hashed payload, utc timestamp, user id) signed
        // with the private key
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append("Method:").append(method).append("\n");
        requestBuilder.append("Hashed Path:").append(new String(base64.encode(DigestUtils.sha1(canonicalUri))).trim()).append("\n");
        requestBuilder.append("X-Ops-Content-Hash:").append(hashedPayload).append("\n");
        requestBuilder.append("X-Ops-Timestamp:").append(datetime).append("\n");
        requestBuilder.append("X-Ops-UserId:").append(this.username);

        logger.debug("Unsigned Canonical Request: \n"+requestBuilder.toString());
        // Sign the resulting string with the private key
        String hashedRequest;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
            byte[] cipherText = cipher.doFinal(requestBuilder.toString().getBytes());
            hashedRequest = new String(base64.encode(cipherText)).trim();
        } catch (Exception e) {
            throw new BridgeError(e);
        }

        /* CREATE THE HTTP REQUEST */
        HttpClient client = HttpClients.custom().setConnectionManager(ChefAdapter.poolingConnManager).build();
        HttpRequestBase request;
        try {
            if (method.toLowerCase().equals("get")) {
                request = new HttpGet(url);
            } else if (method.toLowerCase().equals("post")) {
                request = new HttpPost(url);
                ((HttpPost)request).setEntity(new StringEntity(payload));
            } else {
                throw new BridgeError("Http Method '"+method+"' is not supported");
            }
        } catch (UnsupportedEncodingException e) {
            throw new BridgeError(e);
        }

        /* ADD HEADERS TO HTTP REQUEST */
        request.setHeader("Accept","application/json");
        request.setHeader("Content-Type","application/json");
        String uriPort = uri.getPort() != -1 ? String.valueOf(uri.getPort()) : url.startsWith("https://") ? "443" : "80";
        request.setHeader("Host",uri.getHost()+":"+uriPort);
        request.setHeader("X-Chef-Version","11.4.0");
        request.setHeader("X-Ops-Sign","algorithm=sha1;version=1.0;");
        request.setHeader("X-Ops-Server-API-Version","1");
        request.setHeader("X-Ops-Timestamp",datetime);
        request.setHeader("X-Ops-UserId",this.username);
        request.setHeader("X-Ops-Content-Hash",hashedPayload);

        String[] authorizationChunks = hashedRequest.split("\\n");
        for (int i=0;i<authorizationChunks.length;i++) {
            request.setHeader("X-Ops-Authorization-"+String.valueOf(i+1),authorizationChunks[i].trim());
        }

        HttpResponse response;
        try {
            response = client.execute(request);

            if (response.getStatusLine().getStatusCode() == 401) { // || response.getStatusLine().getStatusCode() == 403) {
                logger.error(EntityUtils.toString(response.getEntity()));
                throw new BridgeError("User not authorized to access this resource. Check the logs for more details.");
            }
        } catch (IOException e) { throw new BridgeError(e); }

        String output = "";
        try {
            output = EntityUtils.toString(response.getEntity());
        } catch (IOException e) {
            throw new BridgeError("Error retrieving the entity from the HttpResponse object",e);
        }

        Map<String,Object> map = new Gson().fromJson(output, Map.class);
        return map;
    }
}