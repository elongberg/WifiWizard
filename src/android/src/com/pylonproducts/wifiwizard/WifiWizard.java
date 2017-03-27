/*
 * Copyright 2015 Matt Parsons
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.pylonproducts.wifiwizard;

import android.net.ConnectivityManager;
import android.net.NetworkRequest;
import android.net.Network;
import android.net.NetworkInfo;
import android.net.NetworkCapabilities;
import android.os.Build;

import java.util.ArrayList;
import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.*;
import android.util.Log;
import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;


public class WifiWizard extends CordovaPlugin {

    private static final String ADD_NETWORK = "addNetwork";
    private static final String REMOVE_NETWORK = "removeNetwork";
    private static final String CONNECT_NETWORK = "connectNetwork";
    private static final String DISCONNECT_NETWORK = "disconnectNetwork";
    private static final String DISCONNECT = "disconnect";
    private static final String LIST_NETWORKS = "listNetworks";
    private static final String START_SCAN = "startScan";
    private static final String GET_SCAN_RESULTS = "getScanResults";
    private static final String GET_CONNECTED_SSID = "getConnectedSSID";
    private static final String IS_WIFI_ENABLED = "isWifiEnabled";
    private static final String SET_WIFI_ENABLED = "setWifiEnabled";
	private static final String ENFORCE_USE_WIFI = "enforceUseWifi";
	private static final String GET_VERSION_SDK = "getVersionSDK";
    private static final String TAG = "WifiWizard";

    private static final int PERMISSION_DENIED_ERROR = 20;
    private static final int COARSE_LOCATION_SEC = 0;

    private JSONArray scanResultData;

    private WifiManager wifiManager;
    private ArrayList<CallbackContext> permissionCallbacks;

	private ConnectivityManager conMan;
	private boolean hasRequestNetwork = false;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        this.wifiManager = (WifiManager) cordova.getActivity().getSystemService(Context.WIFI_SERVICE);
		permissionCallbacks = new ArrayList<CallbackContext>();
		this.conMan = (ConnectivityManager)cordova.getActivity().getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext)
                            throws JSONException {
        if(action.equals(IS_WIFI_ENABLED)) {
            return this.isWifiEnabled(callbackContext);
        }
        else if(action.equals(SET_WIFI_ENABLED)) {
            return this.setWifiEnabled(callbackContext, data);
        }
		else if (action.equals(GET_VERSION_SDK)) {
			return this.getVersionSDK(callbackContext);
		}
        else if (!wifiManager.isWifiEnabled()) {
            callbackContext.error("Wifi is not enabled.");
            return false;
        }
        else if(action.equals(ADD_NETWORK)) {
            return this.addNetwork(callbackContext, data);
        }
        else if(action.equals(REMOVE_NETWORK)) {
            return this.removeNetwork(callbackContext, data);
        }
        else if(action.equals(CONNECT_NETWORK)) {
            return this.connectNetwork(callbackContext, data);
        }
        else if(action.equals(DISCONNECT_NETWORK)) {
            return this.disconnectNetwork(callbackContext, data);
        }
        else if(action.equals(LIST_NETWORKS)) {
            return this.listNetworks(callbackContext);
        }
        else if(action.equals(START_SCAN)) {
            return this.startScan(callbackContext);
        }
        else if(action.equals(GET_SCAN_RESULTS)) {
            if(!PermissionHelper.hasPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION)) {
				this.permissionCallbacks.add(callbackContext);
				// Only allow a single permission request at a time
				if (this.permissionCallbacks.size() <= 1) {
					scanResultData = data;
					PermissionHelper.requestPermission(this, COARSE_LOCATION_SEC, Manifest.permission.ACCESS_COARSE_LOCATION);
					Log.d(TAG, "Location permission not found, requesting from user");
				}
                return true;
            }else{
                return this.getScanResults(callbackContext, data);
            }
        }
        else if(action.equals(DISCONNECT)) {
            return this.disconnect(callbackContext);
        }
        else if(action.equals(GET_CONNECTED_SSID)) {
            return this.getConnectedSSID(callbackContext);
        }
		else if (action.equals(ENFORCE_USE_WIFI)) {
			return this.enforceUseWifi(callbackContext);
		}
        else {
            callbackContext.error("Incorrect action parameter: " + action);
        }

        return false;
    }

    /**
     * This methods adds a network to the list of available WiFi networks.
     * If the network already exists, then it updates it.
     *
     * @params callbackContext     A Cordova callback context.
     * @params data                JSON Array with [0] == SSID, [1] == password
     * @return true    if add successful, false if add fails
     */
    private boolean addNetwork(final CallbackContext callbackContext, final JSONArray data) {
        final WifiWizard that = this;

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                // Initialize the WifiConfiguration object
                WifiConfiguration wifi = new WifiConfiguration();

                Log.d(TAG, "WifiWizard: addNetwork entered.");

                try {
                    // data's order for ANY object is 0: ssid, 1: authentication algorithm,
                    // 2+: authentication information.
                    String authType = data.getString(1);


                    if (authType.equals("WPA")) {
                        // WPA Data format:
                        // 0: ssid
                        // 1: auth
                        // 2: password
                        String newSSID = data.getString(0);
                        wifi.SSID = newSSID;
                        String newPass = data.getString(2);
                        wifi.preSharedKey = newPass;

                        wifi.status = WifiConfiguration.Status.ENABLED;
                        wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                        wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                        wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
                        wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                        wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                        wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                        wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

                        wifi.networkId = ssidToNetworkId(newSSID);

                        if ( wifi.networkId == -1 ) {
                            that.wifiManager.addNetwork(wifi);
                            callbackContext.success(newSSID + " successfully added.");
                        }
                        else {
                            that.wifiManager.updateNetwork(wifi);
                            callbackContext.success(newSSID + " successfully updated.");
                        }

                        that.wifiManager.saveConfiguration();
                        return;
                    }
                    else if (authType.equals("WEP")) {
                        // TODO: connect/configure for WEP
                        Log.d(TAG, "WEP unsupported.");
                        callbackContext.error("WEP unsupported");
                        return;
                    }
                    else if (authType.equals("NONE")) {
                        String newSSID = data.getString(0);
                        wifi.SSID = newSSID;
                        wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                        wifi.networkId = ssidToNetworkId(newSSID);

                        if ( wifi.networkId == -1 ) {
                            that.wifiManager.addNetwork(wifi);
                            callbackContext.success(newSSID + " successfully added.");
                        }
                        else {
                            that.wifiManager.updateNetwork(wifi);
                            callbackContext.success(newSSID + " successfully updated.");
                        }

                        that.wifiManager.saveConfiguration();
                        return;
                    }
                    // TODO: Add more authentications as necessary
                    else {
                        Log.d(TAG, "Wifi Authentication Type Not Supported.");
                        callbackContext.error("Wifi Authentication Type Not Supported: " + authType);
                        return;
                    }
                }
                catch (Exception e) {
                    callbackContext.error(e.getMessage());
                    Log.d(TAG,e.getMessage());
                    return;
                }
            }
        });
        return true;
    }

    /**
     *    This method removes a network from the list of configured networks.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to remove
     *    @return    true if network removed, false if failed
     */
    private boolean removeNetwork(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "WifiWizard: removeNetwork entered.");

        if(!validateData(data)) {
            callbackContext.error("WifiWizard: removeNetwork data invalid");
            Log.d(TAG, "WifiWizard: removeNetwork data invalid");
            return false;
        }

        // TODO: Verify the type of data!
        try {
            String ssidToDisconnect = data.getString(0);

            int networkIdToRemove = ssidToNetworkId(ssidToDisconnect);

            if (networkIdToRemove >= 0) {
                wifiManager.removeNetwork(networkIdToRemove);
                wifiManager.saveConfiguration();
                callbackContext.success("Network removed.");
                return true;
            }
            else {
                callbackContext.error("Network not found.");
                Log.d(TAG, "WifiWizard: Network not found, can't remove.");
                return false;
            }
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }
    }

    /**
     *    This method connects a network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network connected, false if failed
     */
    private boolean connectNetwork(final CallbackContext callbackContext, final JSONArray data) {
		if(!this.validateData(data)) {
			callbackContext.error("WifiWizard: connectNetwork invalid data");
			Log.d(TAG, "WifiWizard: connectNetwork invalid data.");
			return false;
		}
		final WifiWizard that = this;

		cordova.getThreadPool().execute(new Runnable() {
			public void run() {
				Log.d(TAG, "WifiWizard: connectNetwork entered.");

				String ssidToConnect = "";

				try {
					ssidToConnect = data.getString(0);
				}
				catch (Exception e) {
					callbackContext.error(e.getMessage());
					Log.d(TAG, e.getMessage());
					return;
				}

				int networkIdToConnect = ssidToNetworkId(ssidToConnect);

				if (networkIdToConnect >= 0) {
					if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !that.hasRequestNetwork) {
                        // If network has no internet access, this is required to ensure communication goes through it.
                        // This isn't needed for certain android distributions, and on others this still doesn't help
                        // when there is a known internet-ready wifi network available (the system auto-connects to that).
						// Periodically calling this function can help with that, however.
						that.hasRequestNetwork = true;
                        NetworkRequest.Builder req = new NetworkRequest.Builder();
                        req.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
                        conMan.requestNetwork(req.build(), new ConnectivityManager.NetworkCallback() {
                            boolean succeeded = false;
                            Network curNetwork = null;
                            @Override
                            public void onAvailable(Network network) {
                                if (!succeeded) {
                                    succeeded = true;
                                    curNetwork = network;
                                    Log.d(TAG, "Wifi network available, binding... " + network);
                                    conMan.bindProcessToNetwork(network);
                                }
                            }
                            @Override
                            public void onLost(Network network) {
                                if (network.equals(curNetwork)) {
                                    Log.d(TAG, "Lost current network");
                                    conMan.bindProcessToNetwork(null);
                                    succeeded = false;
                                }
                            }
                        });
                    }
				    // Check if already connected
                    WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                    if (wifiInfo.getNetworkId() == networkIdToConnect) {
                        callbackContext.success(wifiInfo.getSupplicantState().toString());
                        return;
                    }
					// Wait until we are actually connected
					// Try 30 times with 250ms sleeps, for a total of 7.5 second long attempt
					for (int i = 0; i <= 30; i++) {
						Log.d(TAG, "Enable network: " + wifiManager.enableNetwork(networkIdToConnect, true));
						wifiInfo = wifiManager.getConnectionInfo();
						if (wifiInfo.getNetworkId() == networkIdToConnect) {
							Log.d(TAG, "Wifi connected");
							callbackContext.success(wifiInfo.getSupplicantState().toString());
							return;
						}
						try {
							Thread.sleep(250);
						} catch (Exception e) {
							Log.d(TAG, e.getMessage());
							callbackContext.error(e.getMessage());
							return;
						}
					}
					Log.d(TAG, "ConnectNetwork: Timed out");
					callbackContext.error("ConnectNetwork: Timed out");
					return;
				} else {
					callbackContext.error("WifiWizard: cannot connect to network");
					return;
				}
			}
		});
		return true;
    }

    /**
     *    This method disconnects a network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network disconnected, false if failed
     */
    private boolean disconnectNetwork(CallbackContext callbackContext, JSONArray data) {
    Log.d(TAG, "WifiWizard: disconnectNetwork entered.");
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }
        String ssidToDisconnect = "";
        // TODO: Verify type of data here!
        try {
            ssidToDisconnect = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }

        int networkIdToDisconnect = ssidToNetworkId(ssidToDisconnect);

        if (networkIdToDisconnect > 0) {
            wifiManager.disableNetwork(networkIdToDisconnect);
            callbackContext.success("Network " + ssidToDisconnect + " disconnected!");
            return true;
        }
        else {
            callbackContext.error("Network " + ssidToDisconnect + " not found!");
            Log.d(TAG, "WifiWizard: Network not found to disconnect.");
            return false;
        }
    }

    /**
     *    This method disconnects current network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if network disconnected, false if failed
     */
    private boolean disconnect(CallbackContext callbackContext) {
        Log.d(TAG, "WifiWizard: disconnect entered.");
        if (wifiManager.disconnect()) {
            callbackContext.success("Disconnected from current network");
            return true;
        } else {
            callbackContext.error("Unable to disconnect from the current network");
            return false;
        }
    }

    /**
     *    This method uses the callbackContext.success method to send a JSONArray
     *    of the currently configured networks.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network disconnected, false if failed
     */
    private boolean listNetworks(CallbackContext callbackContext) {
        Log.d(TAG, "WifiWizard: listNetworks entered.");
        List<WifiConfiguration> wifiList = wifiManager.getConfiguredNetworks();

        JSONArray returnList = new JSONArray();

        for (WifiConfiguration wifi : wifiList) {
            returnList.put(wifi.SSID);
        }

        callbackContext.success(returnList);

        return true;
    }

    /**
       *    This method uses the callbackContext.success method to send a JSONArray
       *    of the scanned networks.
       *
       *    @param    callbackContext        A Cordova callback context
       *    @param    data                   JSONArray with [0] == JSONObject
       *    @return    true
       */
    private boolean getScanResults(final CallbackContext callbackContext, final JSONArray data) {
        final WifiWizard that = this;
		final ArrayList<CallbackContext> ccs = new ArrayList<CallbackContext>();
		ccs.add(callbackContext);

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                that._getScanResults(ccs, data);
            }
        });
        return true;
    }
	private boolean getScanResults() {
        final WifiWizard that = this;
		final JSONArray data = that.scanResultData;

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                that._getScanResults(that.permissionCallbacks, data);
				that.permissionCallbacks.clear();
            }
        });
        return true;
    }

	private void _getScanResults(ArrayList<CallbackContext> ccs, JSONArray data) {
		List<ScanResult> scanResults = wifiManager.getScanResults();

		JSONArray returnList = new JSONArray();

		Integer numLevels = null;

		if(!validateData(data)) {
			for (CallbackContext c : ccs)
				c.error("WifiWizard: getScanResults invalid data");
			Log.d(TAG, "WifiWizard: getScanResults invalid data");
			return;
		}else if (!data.isNull(0)) {
			try {
				JSONObject options = data.getJSONObject(0);

				if (options.has("numLevels")) {
					Integer levels = options.optInt("numLevels");

					if (levels > 0) {
						numLevels = levels;
					} else if (options.optBoolean("numLevels", false)) {
						// use previous default for {numLevels: true}
						numLevels = 5;
					}
				}
			} catch (JSONException e) {
				e.printStackTrace();
				for (CallbackContext c : ccs)
					c.error(e.toString());
				return;
			}
		}

		for (ScanResult scan : scanResults) {
			/*
			 * @todo - breaking change, remove this notice when tidying new release and explain changes, e.g.:
			 *   0.y.z includes a breaking change to WifiWizard.getScanResults().
			 *   Earlier versions set scans' level attributes to a number derived from wifiManager.calculateSignalLevel.
			 *   This update returns scans' raw RSSI value as the level, per Android spec / APIs.
			 *   If your application depends on the previous behaviour, we have added an options object that will modify behaviour:
			 *   - if `(n == true || n < 2)`, `*.getScanResults({numLevels: n})` will return data as before, split in 5 levels;
			 *   - if `(n > 1)`, `*.getScanResults({numLevels: n})` will calculate the signal level, split in n levels;
			 *   - if `(n == false)`, `*.getScanResults({numLevels: n})` will use the raw signal level;
			 */

			int level;

			if (numLevels == null) {
			  level = scan.level;
			} else {
			  level = wifiManager.calculateSignalLevel(scan.level, numLevels);
			}

			JSONObject lvl = new JSONObject();
			try {
				lvl.put("level", level);
				lvl.put("SSID", scan.SSID);
				lvl.put("BSSID", scan.BSSID);
				lvl.put("frequency", scan.frequency);
				lvl.put("capabilities", scan.capabilities);
			   // lvl.put("timestamp", scan.timestamp);
				returnList.put(lvl);
			} catch (JSONException e) {
				e.printStackTrace();
				for (CallbackContext c : ccs)
					c.error(e.toString());
				return;
			}
		}
		for (CallbackContext c : ccs)
			c.success(returnList);
	}

    /**
       *    This method uses the callbackContext.success method. It starts a wifi scanning
       *
       *    @param    callbackContext        A Cordova callback context
       *    @return    true if started was successful
       */
    private boolean startScan(CallbackContext callbackContext) {
        if (wifiManager.startScan()) {
            callbackContext.success();
            return true;
        }
        else {
            callbackContext.error("Scan failed");
            return false;
        }
    }

    /**
     * This method retrieves the SSID for the currently connected network
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if SSID found, false if not.
    */
    private boolean getConnectedSSID(CallbackContext callbackContext){
        if(!wifiManager.isWifiEnabled()){
            callbackContext.error("Wifi is disabled");
            return false;
        }

        WifiInfo info = wifiManager.getConnectionInfo();

        if(info == null){
            callbackContext.error("Unable to read wifi info");
            return false;
        }

        String ssid = info.getSSID();
        if(ssid.isEmpty()) {
            ssid = info.getBSSID();
        }
        if(ssid.isEmpty()){
            callbackContext.error("SSID is empty");
            return false;
        }

        callbackContext.success(ssid.replace("\"", ""));
        return true;
    }

    /**
     * This method retrieves the current WiFi status
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if WiFi is enabled, fail will be called if not.
    */
    private boolean isWifiEnabled(CallbackContext callbackContext) {
        boolean isEnabled = wifiManager.isWifiEnabled();
        callbackContext.success(isEnabled ? "1" : "0");
        return isEnabled;
    }

    /**
     *    This method takes a given String, searches the current list of configured WiFi
     *     networks, and returns the networkId for the network if the SSID matches. If not,
     *     it returns -1.
     */
    private int ssidToNetworkId(String ssid) {
        List<WifiConfiguration> currentNetworks = wifiManager.getConfiguredNetworks();
        int networkId = -1;

        // For each network in the list, compare the SSID with the given one
        for (WifiConfiguration test : currentNetworks) {
            if ( test.SSID.equals(ssid) ) {
                networkId = test.networkId;
            }
        }

        return networkId;
    }

    /**
     *    This method enables or disables the wifi
     */
    private boolean setWifiEnabled(CallbackContext callbackContext, JSONArray data) {
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: setWifiEnabled invalid data");
            Log.d(TAG, "WifiWizard: setWifiEnabled invalid data");
            return false;
        }

        String status = "";

        try {
            status = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }

        if (wifiManager.setWifiEnabled(status.equals("true"))) {
            callbackContext.success();
            return true;
        }
        else {
            callbackContext.error("Cannot enable wifi");
            return false;
        }
    }

	/**
	 * Enforce the use of an available Wi-Fi connection, instead of e.g. mobile data.
	 * Useful in M and above.
	 * Never sends a callback error.
	 */
	private boolean enforceUseWifi(final CallbackContext callbackContext) {
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
			callbackContext.success();
			return true;
		}
		else {
			NetworkRequest.Builder req = new NetworkRequest.Builder();
			req.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
			conMan.requestNetwork(req.build(), new ConnectivityManager.NetworkCallback() {
				boolean succeeded = false;
				@Override
				public void onAvailable(Network network) {
					if (!succeeded) {
						succeeded = true;
						Log.d(TAG, "Wifi network available, binding.");
						Log.d(TAG, "Binding success: " + conMan.bindProcessToNetwork(network));
						callbackContext.success();
					}
				}
			});
		}
		return true;
	}
	
	private boolean getVersionSDK(CallbackContext callbackContext) {
		callbackContext.success(Build.VERSION.SDK_INT);
		return true;
	}

    private boolean validateData(JSONArray data) {
        try {
            if (data == null || data.get(0) == null) {
                return false;
            }
            return true;
        }
        catch (Exception e) {
        }
        return false;
    }

    public void onRequestPermissionResult(int requestCode, String[] permissions,
                                          int[] grantResults) throws JSONException {
        for (int r : grantResults) {
            if (r == PackageManager.PERMISSION_DENIED) {
				PluginResult res = new PluginResult(PluginResult.Status.ERROR, PERMISSION_DENIED_ERROR);
				for (CallbackContext c : this.permissionCallbacks)
					c.sendPluginResult(res);
				this.permissionCallbacks.clear();
                return;
            }
        }

        switch (requestCode) {
            case COARSE_LOCATION_SEC:
                Log.d(TAG, "Location permission granted, returning scan results");
                this.getScanResults();
                this.scanResultData = null;
                break;
        }
    }

}
