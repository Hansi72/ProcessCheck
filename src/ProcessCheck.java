import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.Arrays;

public class ProcessCheck {
    final static String[] validProcesses = {"rust", "valheim"}; //process nickname
    final static String[] processAlias = {"RustDedicated", "valheim_server.x86_64"}; //actual process name in linux system
    static int port = 7201;
    private static final String certPath = "/etc/letsencrypt/live/trygven.no";
    private static final String certPassword = "";
    private static final String userPassword = "";

    public static void main(String[] args) {
        startWebService();
    }

    public static void startWebService() {
        try {
            HttpsServer server = HttpsServer.create(new InetSocketAddress(port), 0);
            SSLContext sslContext = SSLContext.getInstance("TLS");

            File certFile = new File(certPath + "/cert.pem");
            File privKeyFile = new File(certPath + "/privkey.pem");
            KeyStore keyStore = PEMImporter.createKeyStore(privKeyFile, certFile, certPassword);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, certPassword.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                @Override
                public void configure(HttpsParameters params) {
                    try {
                        SSLContext context = getSSLContext();
                        SSLEngine engine = context.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());

                        SSLParameters sslParameters = context.getSupportedSSLParameters();
                        params.setSSLParameters(sslParameters);

                    } catch (Exception e) {
                        System.out.println(e.getMessage());
                    }
                }
            });

            server.createContext("/Status", new StatusHandler());
            server.createContext("/Restart", new RestartHandler());
            server.setExecutor(null);
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Webserver Started");
    }

    static class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Headers headers = exchange.getResponseHeaders();
            headers.add("Access-Control-Allow-Origin", "*");
            OutputStream os = exchange.getResponseBody();

            String query = exchange.getRequestURI().getQuery().toLowerCase();
            if (isValidProcess(query)) {
                exchange.sendResponseHeaders(200, 0);
                if (isProcessRunning(query)) {
                    os.write((
                            "true"
                    ).getBytes("UTF-8"));
                } else {
                    os.write((
                            "false"
                    ).getBytes("UTF-8"));
                }
            } else {
                exchange.sendResponseHeaders(400, 0);
                os.write((
                        "Bad request for query: " + query
                ).getBytes("UTF-8"));
            }
            os.close();
        }
    }

    static class RestartHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Headers headers = exchange.getResponseHeaders();
            headers.add("Access-Control-Allow-Origin", "*");
            OutputStream os = exchange.getResponseBody();

            String[] query = exchange.getRequestURI().getQuery().split("\\+");
            query[1] = query[1].toLowerCase();
            if (isValidProcess(query[1]) && userPassword.equals(query[0])) {
                exchange.sendResponseHeaders(200, 0);
                restartProcess(query[1]);
                os.write((
                        "true"
                ).getBytes("UTF-8"));
            } else {
                exchange.sendResponseHeaders(400, 0);
                os.write((
                        "false"
                ).getBytes("UTF-8"));
            }
            os.close();
        }
    }

    //todo add lock on using this method.
    static void restartProcess(String processName) {
        try {
            while (isProcessRunning(processName)) {
            ProcessBuilder processBuilderKill = new ProcessBuilder("bash", "-c", "kill " + pidOf(processName));
            Process processKill = processBuilderKill.start();
            processKill.waitFor();
            Thread.sleep(500);
            }
            ProcessBuilder processBuilderStart = new ProcessBuilder("bash", "-c", "make " + processName + "Start");
            Process processStart = processBuilderStart.start();
            processStart.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static boolean isValidProcess(String process) {
        for (int i = 0; i < validProcesses.length; i++) {
            if (validProcesses[i].equals(process)) {
                return true;
            }
        }
        return false;
    }

    static boolean isProcessRunning(String processName) {
        if (pidOf(processName).length() < 1) {
            return false;
        } else {
            return true;
        }
    }

    //returns process ID of validProcesses, not aliases
    static String pidOf(String processName) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder("bash", "-c", "pidof " + getProcessAlias(processName));
            Process process = processBuilder.start();
            byte[] bashOutput = process.getInputStream().readAllBytes();
            process.waitFor();
            return new String(bashOutput, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    static String getProcessAlias(String processName) {
        return processAlias[Arrays.binarySearch(validProcesses, processName)];
    }
}
