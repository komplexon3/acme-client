package store

type Store struct {
	setVal chan struct {
		key   string
		value string
		resp  chan error
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

func RunStore() *Store {
	mapping := make(map[string]string)

	store := &Store{
		setVal: make(chan struct {
			key   string
			value string
			resp  chan error
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
				mapping[add.key] = add.value
				add.resp <- nil
			case del := <-store.delVal:
				delete(mapping, del.key)
				del.resp <- nil
			case get := <-store.getVal:
				get.resp <- mapping[get.key]
			}
		}
	}()

	return store
}

func (store *Store) Set(key string, value string) error {
	resp := make(chan error)
	store.setVal <- struct {
		key   string
		value string
		resp  chan error
	}{key, value, resp}
	return <-resp
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
