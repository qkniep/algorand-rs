// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use super::*;

const TESTDIR: &'static str = "testdir_iKywQ1m8eeAVRwURWaR0zQMLIdXSoqfpZlo8Wsuz";

/*#[test]
fn TestSaveThenLoad() {
    let tmp_dir = TempDir::new()?;
    c1, err := loadWithoutDefaults(defaultConfig)
    require.NoError(t, err)
    c1, err = migrate(c1)
    require.NoError(t, err)
    var b1 bytes.Buffer
    ser1 := json.NewEncoder(&b1)
    ser1.Encode(c1)

    os.RemoveAll("testdir")
    err = os.Mkdir("testdir", 0777)
    require.NoError(t, err)

    c1.SaveToDisk("testdir")

    c2, err := LoadConfigFromDisk("testdir")
    require.NoError(t, err)

    var b2 bytes.Buffer
    ser2 := json.NewEncoder(&b2)
    ser2.Encode(c2)

    require.True(t, bytes.Equal(b1.Bytes(), b2.Bytes()))

    os.RemoveAll("testdir")
}*/

#[test]
fn load_missing() {
    let res = Local::load_from_disk(&TESTDIR);
    assert!(res.is_err());
}

/*
#[test]
fn merge_config() {
    let dir = Builder::new()
        .prefix("testdir")
        .rand_bytes(32)
        .tempdir().unwrap();

    c1 := struct {
        GossipFanout              int
        MaxNumberOfTxnsPerAccount int
        NetAddress                string
        ShouldNotExist            int // Ensure we don't panic when config has members we've removed
    }{}
    testInt := int(123)
    testString := "testing123"
    c1.GossipFanout = testInt
    c1.MaxNumberOfTxnsPerAccount = testInt
    c1.NetAddress = testString

    // write our reduced version of the Local struct
    fileToMerge := filepath.Join("testdir", ConfigFilename)
    f, err := os.OpenFile(fileToMerge, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err == nil {
        enc := json.NewEncoder(f)
        err = enc.Encode(c1)
        f.Close()
    }

    require.NoError(t, err)

    // Take defaultConfig and merge with the saved custom settings.
    // This should result in c2 being the same as defaultConfig except for the value(s) in our custom c1
    c2, err := mergeConfigFromDir("testdir", defaultConfig)

    require.NoError(t, err)
    require.Equal(t, defaultConfig.Archival || c1.NetAddress != "", c2.Archival)
    require.Equal(t, defaultConfig.IncomingConnectionsLimit, c2.IncomingConnectionsLimit)
    require.Equal(t, defaultConfig.BaseLoggerDebugLevel, c2.BaseLoggerDebugLevel)

    require.Equal(t, c1.NetAddress, c2.NetAddress)
    require.Equal(t, c1.GossipFanout, c2.GossipFanout)

    os.RemoveAll("testdir")
}
*/
