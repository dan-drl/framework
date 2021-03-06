package elastic

import (
	"encoding/json"

	log "github.com/cihub/seelog"
	"github.com/dan-drl/framework/core/elastic"
	"github.com/dan-drl/framework/core/errors"
	"github.com/dan-drl/framework/core/queue"
)

type ElasticIndexer struct {
	client       elastic.API
	indexChannel string
}

var signalChannel chan bool

func (this *ElasticIndexer) Start() error {

	log.Trace("starting ElasticIndexer")

	signalChannel = make(chan bool, 1)

	go func() {
		defer func() {

			// If the indexer goes down, there's no point in running the crawler. Always
			// panic under this condition. Do not attempt to recover from a panic. The
			// indexing operation now supports a smart backoff anyways, that will retry
			// several times before ultimately giving up.

			// if !global.Env().IsDebug {
			// 	if r := recover(); r != nil {

			// 		if r == nil {
			// 			return
			// 		}
			// 		var v string
			// 		switch r.(type) {
			// 		case error:
			// 			v = r.(error).Error()
			// 		case runtime.Error:
			// 			v = r.(runtime.Error).Error()
			// 		case string:
			// 			v = r.(string)
			// 		}
			// 		log.Error("error in indexer,", v)
			// 	}
			// }
		}()

		for {
			select {
			case <-signalChannel:
				log.Trace("indexer exited")
				return
			default:
				log.Trace("waiting index signal")
				v, er := queue.Pop(this.indexChannel)
				log.Trace("got index signal, ", string(v))
				if er != nil {
					log.Error(er)
					continue
				}
				doc := elastic.IndexDocument{}
				err := json.Unmarshal(v, &doc)
				if err != nil {
					panic(err)
				}

				resp, err := this.client.Index(doc.Index, doc.ID, doc.Source)
				if err != nil {
					panic(errors.New(resp.Result))
				}
			}

		}
	}()

	log.Trace("started ElasticIndexer")

	return nil
}

func (this *ElasticIndexer) Stop() error {
	log.Trace("stopping ElasticIndexer")
	signalChannel <- true
	log.Trace("stopped ElasticIndexer")
	return nil
}
