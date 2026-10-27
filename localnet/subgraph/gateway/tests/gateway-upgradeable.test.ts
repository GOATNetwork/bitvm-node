import {
  assert,
  describe,
  test,
  clearStore,
  beforeAll,
  afterAll
} from "matchstick-as/assembly/index"
import { Address, Bytes, BigInt } from "@graphprotocol/graph-ts"
import { BridgeIn } from "../generated/schema"
import { BridgeIn as BridgeInEvent } from "../generated/GatewayUpgradeable/GatewayUpgradeable"
import { handleBridgeIn } from "../src/gateway-upgradeable"
import { createBridgeInEvent } from "./gateway-upgradeable-utils"

// Tests structure (matchstick-as >=0.5.0)
// https://thegraph.com/docs/en/subgraphs/developing/creating/unit-testing-framework/#tests-structure

describe("Describe entity assertions", () => {
  beforeAll(() => {
    let depositorAddress = Address.fromString(
      "0x0000000000000000000000000000000000000001"
    )
    let instanceId = Bytes.fromI32(1234567890)
    let peginAmountSats = BigInt.fromI32(234)
    let feeAmountSats = BigInt.fromI32(234)
    let newBridgeInEvent = createBridgeInEvent(
      depositorAddress,
      instanceId,
      peginAmountSats,
      feeAmountSats
    )
    handleBridgeIn(newBridgeInEvent)
  })

  afterAll(() => {
    clearStore()
  })

  // For more test scenarios, see:
  // https://thegraph.com/docs/en/subgraphs/developing/creating/unit-testing-framework/#write-a-unit-test

  test("BridgeIn created and stored", () => {
    assert.entityCount("BridgeIn", 1)

    // 0xa16081f360e3847006db660bae1c6d1b2e17ec2a is the default address used in newMockEvent() function
    assert.fieldEquals(
      "BridgeIn",
      "0xa16081f360e3847006db660bae1c6d1b2e17ec2a-1",
      "depositorAddress",
      "0x0000000000000000000000000000000000000001"
    )
    assert.fieldEquals(
      "BridgeIn",
      "0xa16081f360e3847006db660bae1c6d1b2e17ec2a-1",
      "instanceId",
      "1234567890"
    )
    assert.fieldEquals(
      "BridgeIn",
      "0xa16081f360e3847006db660bae1c6d1b2e17ec2a-1",
      "peginAmountSats",
      "234"
    )
    assert.fieldEquals(
      "BridgeIn",
      "0xa16081f360e3847006db660bae1c6d1b2e17ec2a-1",
      "feeAmountSats",
      "234"
    )

    // More assert options:
    // https://thegraph.com/docs/en/subgraphs/developing/creating/unit-testing-framework/#asserts
  })
})
