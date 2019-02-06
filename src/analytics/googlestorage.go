package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"context"


	dt "github.com/trustnetworks/analytics-common/datatypes"
	"github.com/trustnetworks/analytics-common/utils"
	"github.com/trustnetworks/analytics-common/worker"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/storage/v1"
)

const pgm = "googlestorage"

var maxBatch int64
var maxTime float64

type work struct {
	client       *http.Client
	key          string
	project      string
	bucket_name  string
	bucket       *storage.Bucket
	basedir      string
	svc          *storage.Service
	data         []byte
	count        int64
	last         time.Time
	stripPayload bool
}

func (s *work) init() error {

	var err error

	//defualt file size, max time if no batch size and max time env values set
	var defaultMaxBatch int64 = 67108864
	var defaultMaxTime float64 = 1800
	var mBytes = false
	var kBytes = false

	//get batch size env value and  trim, remove spaces and M or K
	mBatchFromEnv := utils.Getenv("MAX_BATCH", "67108864")
	mBatch := strings.Replace(mBatchFromEnv, "\"", "", -1)
	if strings.Contains(strings.ToUpper(mBatch), "M") {
		mBatch = strings.Replace(strings.ToUpper(mBatch), "M", "", -1)
		mBytes = true
	} else if strings.Contains(strings.ToUpper(mBatch), "K") {
		mBatch = strings.Replace(strings.ToUpper(mBatch), "K", "", -1)
		kBytes = true
	}
	mBatch = strings.Replace(mBatch, " ", "", -1)
	mBatch = strings.TrimSpace(mBatch)

	//check max batch size value set in env is parasable to int if not use default value
	maxBatch, err = strconv.ParseInt(mBatch, 10, 64)
	if err != nil {
		maxBatch = defaultMaxBatch
		utils.Log("Couldn't parse MAX_BATCH: %v :using default %v", mBatchFromEnv, defaultMaxBatch)

	} else {
		if mBytes == true {
			maxBatch = maxBatch * 1024 * 1024
		} else if kBytes == true {
			maxBatch = maxBatch * 1024
		}

	}

	utils.Log("maxBatch set to: %v", maxBatch)

	//get max time env value and  trim, remove spaces
	mTimeFromEnv := utils.Getenv("MAX_TIME", "1800")
	mTime := strings.Replace(mTimeFromEnv, "\"", "", -1)
	mTime = strings.Replace(mTime, " ", "", -1)
	mTime = strings.TrimSpace(mTime)

	//check max time value set in env is parasable to int if not use default value
	maxTime, err = strconv.ParseFloat(mTime, 64)
	if err != nil {
		utils.Log("Couldn't parse MAX_TIME: %v :using default %v", mTimeFromEnv, defaultMaxTime)
		maxTime = defaultMaxTime
	}

	utils.Log("maxTime set to: %v", maxTime)

	s.count = 0
	s.last = time.Now()

	s.stripPayload = utils.Getenv("STRIP_PAYLOAD", "false") == "true"

	s.key = utils.Getenv("KEY", "private.json")
	s.project = utils.Getenv("GS_PROJECT", "")
	s.bucket_name = utils.Getenv("GS_BUCKET", "")
	s.basedir = utils.Getenv("GS_BASEDIR", "cyberprobe")

	key, err := ioutil.ReadFile(s.key)
	if err != nil {
		utils.Log("Couldn't read key file: %s", err.Error())
		return err
	}

	config, err := google.JWTConfigFromJSON(key)
	if err != nil {
		utils.Log("JWTConfigFromJSON: %s", err.Error())
		return err
	}

	config.Scopes = []string{storage.DevstorageReadWriteScope}

	s.client = config.Client(oauth2.NoContext)

	s.svc, err = storage.New(s.client)
	if err != nil {
		utils.Log("Coulnd't create client: %s", err.Error())
		return err
	}

	utils.Log("Connected.")

	var bucket storage.Bucket
	bucket.Name = s.bucket_name
	bucket.Kind = "storage#bucket"

	s.bucket, err = s.svc.Buckets.Insert(s.project, &bucket).Do()
	if err != nil {
		utils.Log("Bucket create failed (ignored): %s", err.Error())
	}

	return nil

}

func (s *work) Handle(msg []uint8, w *worker.Worker) error {

	var e dt.Event

	// Convert JSON object to internal object.
	err := json.Unmarshal(msg, &e)
	if err != nil {
		utils.Log("Couldn't unmarshal json: %s", err.Error())
		return nil
	}
	changed := false
	if e.Action == "unrecognised_stream" {
		e.UnrecognisedStream.PayloadB64Length = len(e.UnrecognisedStream.Payload)
		if s.stripPayload {
			e.UnrecognisedStream.Payload = ""
		}
		changed = true
	} else if e.Action == "unrecognised_datagram" {
		e.UnrecognisedDatagram.PayloadB64Length = len(e.UnrecognisedDatagram.Payload)
		if s.stripPayload {
			e.UnrecognisedDatagram.Payload = ""
		}
		changed = true
	} else if s.stripPayload {
		switch e.Action {
		case "icmp":
			e.Icmp.Payload = ""
			changed = true
			break
		case "http_request":
			e.HttpRequest.Body = ""
			changed = true
			break
		case "http_response":
			e.HttpResponse.Body = ""
			changed = true
			break
		case "sip_request":
			e.SipRequest.Payload = ""
			changed = true
			break
		case "sip_response":
			e.SipResponse.Payload = ""
			changed = true
			break
		case "smtp_data":
			e.SmtpData.Data = ""
			changed = true
			break
		}
	}

	if changed {
		msg, err = json.Marshal(&e)
		if err != nil {
			utils.Log("JSON marshal failed: %s", err.Error())
			return nil
		}
	}

	s.data = append(s.data[:], []byte(msg)[:]...)
	s.data = append(s.data[:], []byte{'\n'}[:]...)

	s.count += int64(len(msg))

	if (s.count > maxBatch) || (time.Since(s.last).Seconds() > maxTime) {

		uuid := uuid.New().String()

		// FIXME: Think I want to do GMT here.
		tm := time.Now().Format("2006-01-02/15-04")

		path := s.basedir + "/" + tm + "/" + uuid

		var object storage.Object
		//		object.Bucket = s.bucket_name
		object.Name = path
		object.Kind = "storage#object"
		/*
			object, err := s.svc.Objects.Get(s.bucket_name, path).Do()
			if err != nil {
				utils.Log("Couldn't get: %s", err.Error())
				return err
			}
		*/

		rdr := bytes.NewReader(s.data)

		_, err := s.svc.Objects.Insert(s.bucket_name, &object).
			Media(rdr).Do()

		if err != nil {
			utils.Log("Couldn't insert: %s", err.Error())
		}

		s.data = []byte{}
		s.count = 0
		s.last = time.Now()

	}

	return nil

}

func main() {

	var w worker.QueueWorker
	var s work
	utils.LogPgm = pgm

	utils.Log("Initialising...")

	err := s.init()
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}

	var input string
	var output []string

	if len(os.Args) > 0 {
		input = os.Args[1]
	}
	if len(os.Args) > 2 {
		output = os.Args[2:]
	}

	// context to handle control of subroutines
	ctx := context.Background()
	ctx, cancel := utils.ContextWithSigterm(ctx)
	defer cancel()
	
	err = w.Initialise(ctx, input, output, pgm)
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}

	utils.Log("Initialisation complete.")

	// Invoke Wye event handling.
	err = w.Run(ctx, &s)
	if err != nil {
		utils.Log("error: Event handling failed with err: %s", err.Error())
	}

}
