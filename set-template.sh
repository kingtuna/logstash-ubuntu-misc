curl -XPUT 'http://localhost:9200/_template/template_logstash/' -d @logstash-template.json

curl -XDELETE http://localhost:9200/_template/OLD_template_name?pretty
