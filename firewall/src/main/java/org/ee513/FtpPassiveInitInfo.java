package org.ee513;

public class FtpPassiveInitInfo {
    private long clientIp;
    private long serverIp;
    private int serverPort;
    private boolean validated;

    public FtpPassiveInitInfo(long clientIp, long serverIp, int serverPort) {
        this.clientIp = clientIp;
        this.serverIp = serverIp;
        this.serverPort = serverPort;
        this.validated = false;
    }


    public boolean ipCorresponds(long sIp, long cIp) {
        return (this.serverIp == sIp && this.clientIp == cIp);
    }


    public void validate() {
        this.validated = true;
    }

    public boolean isValidated() {
        return this.validated;
    }

    public void setServerPort(int port) {
        this.serverPort = port;
    }


    @Override
    public boolean equals(Object v) {
        boolean r = false;

        if (v instanceof FtpPassiveInitInfo){
            FtpPassiveInitInfo n = (FtpPassiveInitInfo) v;
            r = (this.serverIp == n.serverIp && this.clientIp == n.clientIp && this.serverPort == n.serverPort && this.validated == n.validated);
        }

        return r;
    }

    @Override
    public int hashCode() {
        int hash = (int) (serverPort + clientIp * 10 + serverIp * 100);
        return hash;
    }

    @Override
    public String toString() {
        return "" + this.serverIp + ":" + this.serverPort + "/" + this.clientIp + " " + validated;
    }


}