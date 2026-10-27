import { newMockEvent } from "matchstick-as"
import { ethereum, Address, Bytes, BigInt } from "@graphprotocol/graph-ts"
import {
  BridgeIn,
  BridgeInRequest,
  CancelWithdraw,
  CommitteeResponse,
  InitWithdraw,
  Initialized,
  PostGraphData,
  ProceedWithdraw,
  WithdrawDisproved,
  WithdrawHappyPath,
  WithdrawUnhappyPath
} from "../generated/GatewayUpgradeable/GatewayUpgradeable"

export function createBridgeInEvent(
  depositorAddress: Address,
  instanceId: Bytes,
  peginAmountSats: BigInt,
  feeAmountSats: BigInt
): BridgeIn {
  let bridgeInEvent = changetype<BridgeIn>(newMockEvent())

  bridgeInEvent.parameters = new Array()

  bridgeInEvent.parameters.push(
    new ethereum.EventParam(
      "depositorAddress",
      ethereum.Value.fromAddress(depositorAddress)
    )
  )
  bridgeInEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  bridgeInEvent.parameters.push(
    new ethereum.EventParam(
      "peginAmountSats",
      ethereum.Value.fromUnsignedBigInt(peginAmountSats)
    )
  )
  bridgeInEvent.parameters.push(
    new ethereum.EventParam(
      "feeAmountSats",
      ethereum.Value.fromUnsignedBigInt(feeAmountSats)
    )
  )

  return bridgeInEvent
}

export function createBridgeInRequestEvent(
  instanceId: Bytes,
  depositorAddress: Address,
  peginAmountSats: BigInt,
  txnFees: Array<BigInt>,
  userInputs: Array<ethereum.Tuple>,
  userXonlyPubkey: Bytes,
  userChangeAddress: string,
  userRefundAddress: string
): BridgeInRequest {
  let bridgeInRequestEvent = changetype<BridgeInRequest>(newMockEvent())

  bridgeInRequestEvent.parameters = new Array()

  bridgeInRequestEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  bridgeInRequestEvent.parameters.push(
    new ethereum.EventParam(
      "depositorAddress",
      ethereum.Value.fromAddress(depositorAddress)
    )
  )
  bridgeInRequestEvent.parameters.push(
    new ethereum.EventParam(
      "peginAmountSats",
      ethereum.Value.fromUnsignedBigInt(peginAmountSats)
    )
  )
  bridgeInRequestEvent.parameters.push(
    new ethereum.EventParam(
      "txnFees",
      ethereum.Value.fromUnsignedBigIntArray(txnFees)
    )
  )
  bridgeInRequestEvent.parameters.push(
    new ethereum.EventParam(
      "userInputs",
      ethereum.Value.fromTupleArray(userInputs)
    )
  )
  bridgeInRequestEvent.parameters.push(
    new ethereum.EventParam(
      "userXonlyPubkey",
      ethereum.Value.fromFixedBytes(userXonlyPubkey)
    )
  )
  bridgeInRequestEvent.parameters.push(
    new ethereum.EventParam(
      "userChangeAddress",
      ethereum.Value.fromString(userChangeAddress)
    )
  )
  bridgeInRequestEvent.parameters.push(
    new ethereum.EventParam(
      "userRefundAddress",
      ethereum.Value.fromString(userRefundAddress)
    )
  )

  return bridgeInRequestEvent
}

export function createCancelWithdrawEvent(
  instanceId: Bytes,
  graphId: Bytes,
  triggerAddress: Address
): CancelWithdraw {
  let cancelWithdrawEvent = changetype<CancelWithdraw>(newMockEvent())

  cancelWithdrawEvent.parameters = new Array()

  cancelWithdrawEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  cancelWithdrawEvent.parameters.push(
    new ethereum.EventParam("graphId", ethereum.Value.fromFixedBytes(graphId))
  )
  cancelWithdrawEvent.parameters.push(
    new ethereum.EventParam(
      "triggerAddress",
      ethereum.Value.fromAddress(triggerAddress)
    )
  )

  return cancelWithdrawEvent
}

export function createCommitteeResponseEvent(
  instanceId: Bytes,
  committeeAddress: Address,
  committeePubkey: Bytes
): CommitteeResponse {
  let committeeResponseEvent = changetype<CommitteeResponse>(newMockEvent())

  committeeResponseEvent.parameters = new Array()

  committeeResponseEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  committeeResponseEvent.parameters.push(
    new ethereum.EventParam(
      "committeeAddress",
      ethereum.Value.fromAddress(committeeAddress)
    )
  )
  committeeResponseEvent.parameters.push(
    new ethereum.EventParam(
      "committeePubkey",
      ethereum.Value.fromBytes(committeePubkey)
    )
  )

  return committeeResponseEvent
}

export function createInitWithdrawEvent(
  instanceId: Bytes,
  graphId: Bytes,
  operatorAddress: Address,
  withdrawAmountSats: BigInt
): InitWithdraw {
  let initWithdrawEvent = changetype<InitWithdraw>(newMockEvent())

  initWithdrawEvent.parameters = new Array()

  initWithdrawEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  initWithdrawEvent.parameters.push(
    new ethereum.EventParam("graphId", ethereum.Value.fromFixedBytes(graphId))
  )
  initWithdrawEvent.parameters.push(
    new ethereum.EventParam(
      "operatorAddress",
      ethereum.Value.fromAddress(operatorAddress)
    )
  )
  initWithdrawEvent.parameters.push(
    new ethereum.EventParam(
      "withdrawAmountSats",
      ethereum.Value.fromUnsignedBigInt(withdrawAmountSats)
    )
  )

  return initWithdrawEvent
}

export function createInitializedEvent(version: BigInt): Initialized {
  let initializedEvent = changetype<Initialized>(newMockEvent())

  initializedEvent.parameters = new Array()

  initializedEvent.parameters.push(
    new ethereum.EventParam(
      "version",
      ethereum.Value.fromUnsignedBigInt(version)
    )
  )

  return initializedEvent
}

export function createPostGraphDataEvent(
  instanceId: Bytes,
  graphId: Bytes
): PostGraphData {
  let postGraphDataEvent = changetype<PostGraphData>(newMockEvent())

  postGraphDataEvent.parameters = new Array()

  postGraphDataEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  postGraphDataEvent.parameters.push(
    new ethereum.EventParam("graphId", ethereum.Value.fromFixedBytes(graphId))
  )

  return postGraphDataEvent
}

export function createProceedWithdrawEvent(
  instanceId: Bytes,
  graphId: Bytes,
  kickoffTxid: Bytes
): ProceedWithdraw {
  let proceedWithdrawEvent = changetype<ProceedWithdraw>(newMockEvent())

  proceedWithdrawEvent.parameters = new Array()

  proceedWithdrawEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  proceedWithdrawEvent.parameters.push(
    new ethereum.EventParam("graphId", ethereum.Value.fromFixedBytes(graphId))
  )
  proceedWithdrawEvent.parameters.push(
    new ethereum.EventParam(
      "kickoffTxid",
      ethereum.Value.fromFixedBytes(kickoffTxid)
    )
  )

  return proceedWithdrawEvent
}

export function createWithdrawDisprovedEvent(
  instanceId: Bytes,
  graphId: Bytes,
  disproveTxType: i32,
  txnIndex: BigInt,
  challengeStartTxid: Bytes,
  challengeFinishTxid: Bytes,
  challengerAddress: Address,
  disproverAddress: Address,
  challengerRewardAmount: BigInt,
  disproverRewardAmount: BigInt
): WithdrawDisproved {
  let withdrawDisprovedEvent = changetype<WithdrawDisproved>(newMockEvent())

  withdrawDisprovedEvent.parameters = new Array()

  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam("graphId", ethereum.Value.fromFixedBytes(graphId))
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "disproveTxType",
      ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(disproveTxType))
    )
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "txnIndex",
      ethereum.Value.fromUnsignedBigInt(txnIndex)
    )
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "challengeStartTxid",
      ethereum.Value.fromFixedBytes(challengeStartTxid)
    )
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "challengeFinishTxid",
      ethereum.Value.fromFixedBytes(challengeFinishTxid)
    )
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "challengerAddress",
      ethereum.Value.fromAddress(challengerAddress)
    )
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "disproverAddress",
      ethereum.Value.fromAddress(disproverAddress)
    )
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "challengerRewardAmount",
      ethereum.Value.fromUnsignedBigInt(challengerRewardAmount)
    )
  )
  withdrawDisprovedEvent.parameters.push(
    new ethereum.EventParam(
      "disproverRewardAmount",
      ethereum.Value.fromUnsignedBigInt(disproverRewardAmount)
    )
  )

  return withdrawDisprovedEvent
}

export function createWithdrawHappyPathEvent(
  instanceId: Bytes,
  graphId: Bytes,
  take1Txid: Bytes,
  operatorAddress: Address,
  rewardAmountSats: BigInt
): WithdrawHappyPath {
  let withdrawHappyPathEvent = changetype<WithdrawHappyPath>(newMockEvent())

  withdrawHappyPathEvent.parameters = new Array()

  withdrawHappyPathEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  withdrawHappyPathEvent.parameters.push(
    new ethereum.EventParam("graphId", ethereum.Value.fromFixedBytes(graphId))
  )
  withdrawHappyPathEvent.parameters.push(
    new ethereum.EventParam(
      "take1Txid",
      ethereum.Value.fromFixedBytes(take1Txid)
    )
  )
  withdrawHappyPathEvent.parameters.push(
    new ethereum.EventParam(
      "operatorAddress",
      ethereum.Value.fromAddress(operatorAddress)
    )
  )
  withdrawHappyPathEvent.parameters.push(
    new ethereum.EventParam(
      "rewardAmountSats",
      ethereum.Value.fromUnsignedBigInt(rewardAmountSats)
    )
  )

  return withdrawHappyPathEvent
}

export function createWithdrawUnhappyPathEvent(
  instanceId: Bytes,
  graphId: Bytes,
  take2Txid: Bytes,
  operatorAddress: Address,
  rewardAmountSats: BigInt
): WithdrawUnhappyPath {
  let withdrawUnhappyPathEvent = changetype<WithdrawUnhappyPath>(newMockEvent())

  withdrawUnhappyPathEvent.parameters = new Array()

  withdrawUnhappyPathEvent.parameters.push(
    new ethereum.EventParam(
      "instanceId",
      ethereum.Value.fromFixedBytes(instanceId)
    )
  )
  withdrawUnhappyPathEvent.parameters.push(
    new ethereum.EventParam("graphId", ethereum.Value.fromFixedBytes(graphId))
  )
  withdrawUnhappyPathEvent.parameters.push(
    new ethereum.EventParam(
      "take2Txid",
      ethereum.Value.fromFixedBytes(take2Txid)
    )
  )
  withdrawUnhappyPathEvent.parameters.push(
    new ethereum.EventParam(
      "operatorAddress",
      ethereum.Value.fromAddress(operatorAddress)
    )
  )
  withdrawUnhappyPathEvent.parameters.push(
    new ethereum.EventParam(
      "rewardAmountSats",
      ethereum.Value.fromUnsignedBigInt(rewardAmountSats)
    )
  )

  return withdrawUnhappyPathEvent
}
