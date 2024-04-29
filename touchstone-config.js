function getMatchingTouchstoneTestServer(requestUrl, touchstoneConfig) {
    const parsedUrl = new URL(requestUrl)
    var returnConfig = null
    console.log(`Looking up touchstone config for request: ${requestUrl}`)

    if(touchstoneConfig[parsedUrl.hostname]){
        console.log(`Found touchstone config for hostname: ${parsedUrl.hostname}`)
        //There could be multiple server paths for a given hostname, so let's loop through one at a time.
        //It is assumed that the paths are in priority order, and have no conflicts between them.
        for(var i=0;i<touchstoneConfig[parsedUrl.hostname].length; i++) {
            if(requestUrl.startsWith(touchstoneConfig[parsedUrl.hostname][i].BASE_URL)) {
                console.log(`Found touchstone config with base url: ${touchstoneConfig[parsedUrl.hostname][i].BASE_URL}`)
                returnConfig = touchstoneConfig[parsedUrl.hostname][i]
            }
        }
    }
    else {
        console.log(`No touchstone config matches for hostname: ${parsedUrl.hostname}`)
    }
    return returnConfig
}
module.exports.getMatchingTouchstoneTestServer = getMatchingTouchstoneTestServer