<!--
SPDX-FileCopyrightText: 2019-present Open Networking Foundation <info@opennetworking.org>

SPDX-License-Identifier: Apache-2.0
-->

# Proto generated from ASN1

The files in this folder are generated by:

* converting the `E2AP-<version>.asn1` file in to a single `proto` file using `asn1c -B`
* splitting this single `proto` file in to 6 parts using `csplit`
* renaming the 6 `proto` files to replace `-` in their names with `_`
* editing the 6 `proto` files to fix their paths and packages
* add the license header to the 6 `proto` files
* modifying the 6 `proto` files to fix mistakes
* updating the `compile_protos.sh` script to include these 6 `proto` files
* running `make protos` to generate Go code in this directory
* creating an `e2ap_procedure_codes.go` for constants
* running `make test` to ensure all of the Go code compiles properly

All of these are described in detail below.

Once all these have been done, the conversion of the `asn1` to C file can be done with
```bash
asn1c -fcompound-names -fincludes-quoted -fno-include-deps -findirect-choice -gen-PER -no-gen-OER -D. <filename>.asn1`
```

## Converting the `E2AP-<version>.asn1` file

Assuming the ASN1 file is at
* `~/eclipse-workspace/asn1-files/e2ap-v01.01.00.asn1`

AND the `asn1c` compiler from the ONF fork of this tool https://github.com/onosproject/asn1c
has been compiled to:
* `~/git/vlm/asn1c/asn1c/asn1c`

AND this `onos-e2t` project has been checked out into:
* `~/go/src/github.com/onosproject/onos-e2t`

THEN perform the conversion by
```bash
cd ~/eclipse-workspace/asn1-files
~/git/vlm/asn1c/asn1c/asn1c -B e2ap-v01.01.00.asn1 > ~/go/src/github.com/onosproject/onos-e2t/api/e2ap/v1beta2/e2ap-v01.01.00.proto
```

> This might produce some warnings like:
>
> `WARNING: Parameterized type E2AP-PROTOCOL-IES expected for E2AP-PROTOCOL-IES at line 1716 in e2ap-v01.01.00.asn1`
>
> these can be safely ignored

> On the version of the ASN1 file copied from the Word document *O-RAN.WG3.E2AP-v01.01.docx* there are 12 places where an linefeed character **0x0A** is used for the "whitespace" character - this will cause the asn1c tool to fail.
>
> e.g. in the definition `e2connectionUpdate      E2AP-ELEMENTARY-PROCEDURE ::= {`
the 6th and 2nd last characters are guilty.
>
> Replace all such characters with whitespace.

## Splitting this single `proto` file
Run
```bash
cd ~/go/src/github.com/onosproject/onos-e2t/api/e2ap/v1beta2/

../../../build/bin/csplit-protos.sh e2ap-v01.01.00.proto

rm xx00 e2ap-v01.01.00.proto
```

If you are running MacOS, then you should comment line 35 and uncomment line 37 of csplit-protos.sh.
There are some prerequisites you have to install. For more explanation, see help:
```bash
./csplit-protos.sh -h.
```

6 files are created:

* e2ap-pdu-descriptions.proto
* e2ap-pdu-contents.proto
* e2ap-ies.proto
* e2ap-commondatatypes.proto
* e2ap-constants.proto
* e2ap-containers.proto

## Renaming the 6 `proto` files
Change the names of the files above to replace `-` with `_`
```bash
for f in e2ap-*.proto; do
newname="${f//-/_}";
mv $f $newname;
sed -i "s/$f/$newname/g" e2ap*.proto
done
```

## Editing to fix paths, packages and imports
For GNU-based OS run:
```bash
sed -i "s/package e2ap_v01_01_00_asn1.v1/package e2ap.v1beta2/" e2ap*.proto
sed -i "s/option go_package = \"e2ap_v01_01_00_asn1\/v1/option go_package = \"github.com\/onosproject\/onos-e2t\/api\/e2ap\/v1beta2/" e2ap*.proto
sed -i "s/import \"e2ap_v01_01_00_asn1\/v1/import \"e2ap\/v1beta2/g" e2ap*.proto
```
For MacOS run:
```bash
sed -i '' -e 's/package e2ap_v01_01_00_asn1.v1/package e2ap.v1beta2/' e2ap*.proto
sed -i '' -e "s/option go_package = \"e2ap_v01_01_00_asn1\/v1/option go_package = \"github.com\/onosproject\/onos-e2t\/api\/e2ap\/v1beta2/" e2ap*.proto
sed -i '' -e "s/import \"e2ap_v01_01_00_asn1\/v1/import \"e2ap\/v1beta2/g" e2ap*.proto
```

## Add the license header
```bash
for f in e2ap_*.proto;
do echo -e "$(cat ../../../../build-tools/licensing/boilerplates/Apache-2.0/boilerplate.proto.txt)""\n" | cat - $f > temp && mv temp $f;
sed -i "0,/YEAR/s//2021/" $f
done
```

## Modifying the 6 `proto` files to fix mistakes
Currently there are too many mistakes to list. Generally they are in the categories:
* In `e2ap_containers.proto`
  * The type `ProtocolIeField001` should have `RequestID` and `Criticiality` (cast all types to `int32`)
  * The type `ProtocolIeFieldPair` should have `RequestID` and `Criticiality` (cast all types to `int32`)
  * The type `ProtocolIeContainerList` should be use `ProtocolIeSingleContainer001`
* in `e2ap_pdu_contents.proto`
  * places where nested templates are used in ASN1. Top level templates can be resolved fine
  * this leads to `ProtocolIeContainer` type being specified where `<parentname>Ies` should be used
  * e.g. in `RicsubscriptionRequest` should have `RicsubscriptionRequestIes protocol_ies = 1;`
  * and `ProtocolIeSingleContainer` being specified where `<parentname-without-List>ItemIes` should be used
  * e.g. in `RicactionsToBeSetupList` should have `repeated RicactionToBeSetupItemIes value = 1 [(validate.v1.rules).repeated = { max_items: 16}];`
  * ItemIEs lacking child details e.g. `message RicactionToBeSetupItemIes` should be
```
message RicactionToBeSetupItemIes {
    //@inject_tag: aper:"valueLB:0,valueUB:65535,unique"
    int32 id = 1 [(validate.v1.rules).int32.const = 19, json_name="id"];
    //@inject_tag: aper:"valueLB:0,valueUB:2"
    int32 criticality = 2 [(validate.v1.rules).int32.const = 1, json_name="criticality"];
    // @inject_tag: aper:"canonicalOrder"
    RicactionToBeSetupItemIe value = 3 [json_name="ricActionToBeSetupItem"];
};
```
* In `e2ap_ies.proto`:
  * in some places `int32` is specified and it should be `int64`
  * `ProtocolIeField001` can be safely removed, if any is present
* In `e2ap_commondatatypes.proto` there are places where
  * `BasicOID` type is not defined - cast it with a `string`
* In `e2ap_pdu_descriptions.proto`:
  * String starting with `@` need to be commented out
  * message types that need to be renamed with a suffix `Ep` because they
    clash with a message type defined elsewhere
  * There is a need to do slight recomposition of the top-level messages with regard to
    [this example](https://github.com/onosproject/onos-e2t/blob/a67d225182089e46eecd39a6be4dc71a35562168/api/e2ap/v2/e2ap_pdu_descriptions.proto#L36-L75)
    * Once `InitiatingMessage`, `SuccessfulOutcome` and `UnsuccessfulOutcome` are recomposed accordingly, rest of this Protobuf can be deleted

These will be handled by updating the asn1c tool - see:
[SDRAN-37](https://jira.opennetworking.org/browse/SDRAN-37)

> To see the kind of differences, run the commands above to overwrite the
> exiting files and inspect with `git diff` to see where edits have been made

## Updating the `compile_protos.sh`
Update the script with the new protos

## Running `make protos`
This will generate Go code from the 6 `proto` files
```bash
cd ~/go/src/github.com/onosproject/onos-e2t
make protos
```

This runs `buf lint` on the `proto` files to make sure they are formatted properly and
the runs `compile_protos.sh`

The expected output is like:
```bash
docker run -it -v `pwd`:/go/src/github.com/onosproject/onos-e2t \
	-w /go/src/github.com/onosproject/onos-e2t/api \
	bufbuild/buf:0.27.1 check lint
docker run -it -v `pwd`:/go/src/github.com/onosproject/onos-e2t \
	-w /go/src/github.com/onosproject/onos-e2t \
	--entrypoint build/bin/compile-protos.sh \
	onosproject/protoc-go:v0.6.7
api/e2ap/v1beta1/e2ap_constants.proto:16:1: warning: Import e2ap/v1beta1/e2ap_commondatatypes.proto is unused.
api/e2ap/v1beta1/e2ap_containers.proto:18:1: warning: Import validate/v1/validate.proto is unused.
api/e2ap/v1beta1/e2ap_ies.proto:17:1: warning: Import e2ap/v1beta1/e2ap_constants.proto is unused.
api/e2ap/v1beta1/e2ap_pdu_contents.proto:17:1: warning: Import e2ap/v1beta1/e2ap_containers.proto is unused.
api/e2ap/v1beta1/e2ap_pdu_contents.proto:18:1: warning: Import e2ap/v1beta1/e2ap_constants.proto is unused.
api/e2ap/v1beta1/e2ap_pdu_descriptions.proto:19:1: warning: Import validate/v1/validate.proto is unused.
api/e2ap/v1beta2/e2ap_constants.proto:16:1: warning: Import e2ap/v1beta2/e2ap_commondatatypes.proto is unused.
api/e2ap/v1beta2/e2ap_containers.proto:18:1: warning: Import validate/v1/validate.proto is unused.
api/e2ap/v1beta2/e2ap_ies.proto:17:1: warning: Import e2ap/v1beta2/e2ap_constants.proto is unused.
api/e2ap/v1beta2/e2ap_pdu_contents.proto:17:1: warning: Import e2ap/v1beta2/e2ap_containers.proto is unused.
api/e2ap/v1beta2/e2ap_pdu_contents.proto:18:1: warning: Import e2ap/v1beta2/e2ap_constants.proto is unused.
api/e2ap/v1beta2/e2ap_pdu_descriptions.proto:19:1: warning: Import validate/v1/validate.proto is unused.
```

## Creating an `e2ap_procedure_codes.go`
This `go` file is convenient for accessing constants defined in the `ASN1` definition

It contains 2 enums:

* ProcedureCodeT
* ProtocolIeID

and is generated by hand.

## Run `make test` to ensure Go builds properly
This will call the `deps` target to run `go build -v ./...`

> You can run `go build -v ./...` directly instead
