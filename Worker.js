// @ts-nocheck
// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.
// @ts-ignore

import { connect } from "cloudflare:sockets";

// How to generate your own UUID:
// https://www.uuidgenerator.net/
let userID = "e88fd9e3-a7ce-48d6-bfc9-d7ef47f2cf2b";

const proxyIPs = [
    "104.17.24.0",
    "104.17.24.1",
    "104.17.24.10",
    "188.164.248.12",
    "172.67.184.209",
    "185.38.135.36",
    "8.219.201.174",
    "8.222.138.164",
];

let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

let dohURL = "https://cloudflare-dns.com/dns-query";

// v2board api environment variables
let nodeId = ""; // 1

let apiToken = ""; //abcdefghijklmnopqrstuvwxyz123456

let apiHost = ""; // api.v2board.com

if (!isValidUUID(userID)) {
    throw new Error("uuid is not valid");
}

export default {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        try {
            userID = env.UUID || userID;
            proxyIP = env.PROXYIP || proxyIP;
            dohURL = env.DNS_RESOLVER_URL || dohURL;
            nodeId = env.NODE_ID || nodeId;
            apiToken = env.API_TOKEN || apiToken;
            apiHost = env.API_HOST || apiHost;
            const upgradeHeader = request.headers.get("Upgrade");

            if (!upgradeHeader || upgradeHeader !== "websocket") {
                const url = new URL(request.url);
                const searchParams = new URLSearchParams(url.search);
                const fragmentLength = searchParams.get("length");
                const fragmentInterval = searchParams.get("interval");
                const dnsAddress = searchParams.get("dns");
                const client = searchParams.get("app");
                const configAddr = searchParams.get("addr");

                switch (url.pathname) {
                    case "/cf":
                        return new Response(JSON.stringify(request.cf, null, 4), {
                            status: 200,
                            headers: {
                                "Content-Type": "application/json;charset=utf-8",
                            },
                        });
                    case "/connect": // for test connect to cf socket
                        const [hostname, port] = ["cloudflare.com", "80"];
                        console.log(`Connecting to ${hostname}:${port}...`);

                        try {
                            const socket = await connect({
                                hostname: hostname,
                                port: parseInt(port, 10),
                            });

                            const writer = socket.writable.getWriter();

                            try {
                                await writer.write(
                                    new TextEncoder().encode(
                                        "GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"
                                    )
                                );
                            } catch (writeError) {
                                writer.releaseLock();
                                await socket.close();
                                return new Response(writeError.message, { status: 500 });
                            }

                            writer.releaseLock();

                            const reader = socket.readable.getReader();
                            let value;

                            try {
                                const result = await reader.read();
                                value = result.value;
                            } catch (readError) {
                                await reader.releaseLock();
                                await socket.close();
                                return new Response(readError.message, { status: 500 });
                            }

                            await reader.releaseLock();
                            await socket.close();

                            return new Response(new TextDecoder().decode(value), {
                                status: 200,
                            });
                        } catch (connectError) {
                            return new Response(connectError.message, { status: 500 });
                        }
                    case `/sub/${userID}`: {
                        const vlessConfigs = await getVLESSConfig(
                            userID,
                            request.headers.get("Host"),
                            client
                        );

                        return new Response(`${vlessConfigs}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            },
                        });
                    }
                    case `/frag/${userID}`:

                        const configs = await getFragVLESSConfig(userID, request.headers.get("Host"), fragmentLength, fragmentInterval, dnsAddress);
                        const config = configs.filter(conf => conf.address == configAddr)[0].fragConf;

                        return new Response(`${JSON.stringify(config)}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            },
                        });

                    case `/${userID}`:
                        if (request.method === "POST") {
                            const formData = await request.formData();
                            const dns = formData.get("dns");
                            const lengthMin = formData.get("fragmentLengthMin");
                            const lengthMax = formData.get("fragmentLengthMax");
                            const intervalMin = formData.get("fragmentIntervalMin");
                            const intervalMax = formData.get("fragmentIntervalMax");

                            const html = await renderPage(
                                userID,
                                request.headers.get("Host"),
                                dns,
                                lengthMin,
                                lengthMax,
                                intervalMin,
                                intervalMax,
                                url.pathname
                            );

                            return new Response(html, {
                                status: 200,
                                headers: {
                                    "Content-Type": "text/html",
                                },
                            });
                        } else {
                            const html = await renderPage(
                                userID,
                                request.headers.get("Host"),
                                false,
                                "100",
                                "200",
                                "10",
                                "20"
                            );
                            return new Response(html, {
                                status: 200,
                                headers: {
                                    "Content-Type": "text/html",
                                },
                            });
                        }
                    default:
                        // return new Response('Not found', { status: 404 });
                        // For any other path, reverse proxy to 'www.fmprc.gov.cn' and return the original response
                        url.hostname = "www.bing.com";
                        url.protocol = "https:";
                        request = new Request(url, request);
                        return await fetch(request);
                }
            } else {
                return await vlessOverWSHandler(request);
            }
        } catch (err) {
      /** @type {Error} */ let e = err;
            return new Response(e.toString());
        }
    },
};

/**
 *
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function vlessOverWSHandler(request) {
    /** @type {import("@cloudflare/workers-types").WebSocket[]} */
    // @ts-ignore
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const log = (
    /** @type {string} */ info,
    /** @type {string | undefined} */ event
    ) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

    const readableWebSocketStream = makeReadableWebSocketStream(
        webSocket,
        earlyDataHeader,
        log
    );

    /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDns = false;

    // ws --> remote
    readableWebSocketStream
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (isDns && udpStreamWrite) {
                        return udpStreamWrite(chunk);
                    }
                    if (remoteSocketWapper.value) {
                        const writer = remoteSocketWapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    const {
                        hasError,
                        message,
                        portRemote = [
                            443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880, 2052, 2082,
                            2086, 2095,
                        ],
                        addressRemote = "",
                        rawDataIndex,
                        vlessVersion = new Uint8Array([0, 0]),
                        isUDP,
                    } = await processVlessHeader(chunk, userID);
                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "
                        } `;
                    if (hasError) {
                        // controller.error(message);
                        throw new Error(message); // cf seems has bug, controller.error will not end stream
                        // webSocket.close(1000, message);
                        return;
                    }
                    // if UDP but port not DNS port, close it
                    if (isUDP) {
                        if (portRemote === 53) {
                            isDns = true;
                        } else {
                            // controller.error('UDP proxy only enable for DNS which is port 53');
                            throw new Error("UDP proxy only enable for DNS which is port 53"); // cf seems has bug, controller.error will not end stream
                            return;
                        }
                    }
                    // ["version", "附加信息长度 N"]
                    const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
                    const rawClientData = chunk.slice(rawDataIndex);

                    // TODO: support udp here when cf runtime has udp support
                    if (isDns) {
                        const { write } = await handleUDPOutBound(
                            webSocket,
                            vlessResponseHeader,
                            log
                        );
                        udpStreamWrite = write;
                        udpStreamWrite(rawClientData);
                        return;
                    }
                    handleTCPOutBound(
                        remoteSocketWapper,
                        addressRemote,
                        portRemote,
                        rawClientData,
                        webSocket,
                        vlessResponseHeader,
                        log
                    );
                },
                close() {
                    log(`readableWebSocketStream is close`);
                },
                abort(reason) {
                    log(`readableWebSocketStream is abort`, JSON.stringify(reason));
                },
            })
        )
        .catch((err) => {
            log("readableWebSocketStream pipeTo error", err);
        });

    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

let apiResponseCache = null;
let cacheTimeout = null;

/**
 * Fetches the API response from the server and caches it for future use.
 * @returns {Promise<object|null>} A Promise that resolves to the API response object or null if there was an error.
 */
async function fetchApiResponse() {
    const requestOptions = {
        method: "GET",
        redirect: "follow",
    };

    try {
        const response = await fetch(
            `https://${apiHost}/api/v1/server/UniProxy/user?node_id=${nodeId}&node_type=v2ray&token=${apiToken}`,
            requestOptions
        );

        if (!response.ok) {
            console.error("Error: Network response was not ok");
            return null;
        }
        const apiResponse = await response.json();
        apiResponseCache = apiResponse;

        // Refresh the cache every 5 minutes (300000 milliseconds)
        if (cacheTimeout) {
            clearTimeout(cacheTimeout);
        }
        cacheTimeout = setTimeout(() => fetchApiResponse(), 300000);

        return apiResponse;
    } catch (error) {
        console.error("Error:", error);
        return null;
    }
}

/**
 * Returns the cached API response if it exists, otherwise fetches the API response from the server and caches it for future use.
 * @returns {Promise<object|null>} A Promise that resolves to the cached API response object or the fetched API response object, or null if there was an error.
 */
async function getApiResponse() {
    if (!apiResponseCache) {
        return await fetchApiResponse();
    }
    return apiResponseCache;
}

/**
 * Checks if a given UUID is present in the API response.
 * @param {string} targetUuid The UUID to search for.
 * @returns {Promise<boolean>} A Promise that resolves to true if the UUID is present in the API response, false otherwise.
 */
async function checkUuidInApiResponse(targetUuid) {
    // Check if any of the environment variables are empty
    if (!nodeId || !apiToken || !apiHost) {
        return false;
    }

    try {
        const apiResponse = await getApiResponse();
        if (!apiResponse) {
            return false;
        }
        const isUuidInResponse = apiResponse.users.some(
            (user) => user.uuid === targetUuid
        );
        return isUuidInResponse;
    } catch (error) {
        console.error("Error:", error);
        return false;
    }
}

// Usage example:
//   const targetUuid = "65590e04-a94c-4c59-a1f2-571bce925aad";
//   checkUuidInApiResponse(targetUuid).then(result => console.log(result));

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    vlessResponseHeader,
    log
) {
    async function connectAndWrite(address, port) {
        /** @type {import("@cloudflare/workers-types").Socket} */
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData); // first write, nomal is tls client hello
        writer.releaseLock();
        return tcpSocket;
    }

    // if the cf connect tcp socket have no incoming data, we retry to redirect ip
    async function retry() {
        const tcpSocket = await connectAndWrite(
            proxyIP || addressRemote,
            portRemote
        );
        // no matter retry success or not, close websocket
        tcpSocket.closed
            .catch((error) => {
                console.log("retry tcpSocket closed error", error);
            })
            .finally(() => {
                safeCloseWebSocket(webSocket);
            });
        remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 *
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader for ws 0rtt
 * @param {(info: string)=> void} log for ws 0rtt
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            // The event means that the client closed the client -> server stream.
            // However, the server -> client stream is still open until you call close() on the server side.
            // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
            webSocketServer.addEventListener("close", () => {
                // client send close, need close server
                // if stream is cancel, skip controller.close
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer has error");
                controller.error(err);
            });
            // for ws 0rtt
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
            // if ws can stop read if stream is full, we can implement backpressure
            // https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },
        cancel(reason) {
            // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
            // 2. if readableStream is cancel, all controller.close/enqueue need skip,
            // 3. but from testing controller.error still work even if readableStream is canc
