var ModSecLog2JSON = require('./app/lib/ModSecLog2JSON.js')
var client = require('./connection.js');  
var os = require('os');

client.cluster.health({},function(err,resp,status) {  
    console.log(resp);
});

var log2json = new ModSecLog2JSON();
log_location = "/var/log/apache2/modsec_audit.log"


log2json.async(log_location, function callback(jsonArray){
    //divide in batch and send via bulk one by one
    let i = 0;
    let FACTOR=100
    let dividend = Math.ceil(jsonArray.length/FACTOR);

    //avoid multiply zero
    if(dividend == 0) {
        dividend = 1;
    }

    for(k = 1; k <= dividend; k++) {
        let batchIndex = k; //needed because of async calls
        let bodyData = [];
        let batchUpperLimit = Math.ceil(k*(jsonArray.length/dividend));

        for(i; i < batchUpperLimit; i++){
            jsonArray[i]['server'] = os.hostname()
            bodyData.push({index:{ _index: 'test_index_3', _type: 'log', _id: jsonArray[i].id2}})
            bodyData.push(jsonArray[i]);
        }
        i++;
        // console.log(bodyData.length)
        // console.log(JSON.stringify(bodyData))

        client.bulk({
            body: bodyData
          }, function (err, resp, status) {
            if(err) {
                console.log("Error bulk number " + batchIndex + " : " + err);
            }
            console.log("End bulk " + batchIndex + " status "+ status);
            //console.log(resp);
        });
    }
})
