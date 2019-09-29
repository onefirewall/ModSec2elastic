var elasticsearch=require('elasticsearch');

var client = new elasticsearch.Client( {  
  hosts: [
    'https://user:pass@elk.server.com/elasticsearch'
  ]
});

module.exports = client;  