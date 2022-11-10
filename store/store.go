package store

import "github.com/sirupsen/logrus"

type Store struct {
	setVal chan struct {
		key      string
		value    string
		err      chan error
		tripwire chan bool
	}
	delVal chan struct {
		key  string
		resp chan error
	}
	getVal chan struct {
		key  string
		resp chan string
	}
}

func RunStore(logger *logrus.Entry) *Store {
	mapping := make(map[string]struct {
		val      string
		tripwire chan bool
	})

	store := &Store{
		setVal: make(chan struct {
			key      string
			value    string
			err      chan error
			tripwire chan bool
		}),
		delVal: make(chan struct {
			key  string
			resp chan error
		}),
		getVal: make(chan struct {
			key  string
			resp chan string
		}),
	}

	go func() {
		for {
			select {
			case add := <-store.setVal:
				logger.Debugf("Adding key %s with value %s", add.key, add.value)
				mapping[add.key] = struct {
					val      string
					tripwire chan bool
				}{
					val:      add.value,
					tripwire: add.tripwire,
				}
				add.err <- nil
			case del := <-store.delVal:
				logger.Debugf("Deleting key %s", del.key)
				delete(mapping, del.key)
				del.resp <- nil
			case get := <-store.getVal:
				logger.Debugf("Getting key %s -> value", get.key, mapping[get.key].val)
				get.resp <- mapping[get.key].val
				// signal that someone read this value
				select {
				case mapping[get.key].tripwire <- true:
					// signal sent
				default:
					// no signal sent bc we already sent one and the channel is full
				}
			}
		}
	}()

	return store
}

func (store *Store) Set(key string, value string) (chan bool, error) {
	err := make(chan error)
	tripwire := make(chan bool)
	store.setVal <- struct {
		key      string
		value    string
		err      chan error
		tripwire chan bool
	}{key, value, err, tripwire}
	return tripwire, <-err
}

func (store *Store) Del(key string) error {
	resp := make(chan error)
	store.delVal <- struct {
		key  string
		resp chan error
	}{key, resp}
	return <-resp
}

func (store *Store) Get(key string) string {
	resp := make(chan string)
	store.getVal <- struct {
		key  string
		resp chan string
	}{key, resp}
	return <-resp
}
